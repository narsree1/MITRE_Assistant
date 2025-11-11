# gap_analysis.py - AI-Powered Coverage Gap Analysis with Claude API

import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Tuple
import torch
import requests
import json

def call_claude_api(prompt: str, api_key: str, model: str = "claude-sonnet-4-20250514") -> str:
    """
    Call Claude API with a given prompt
    """
    try:
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        data = {
            "model": model,
            "max_tokens": 4096,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=data,
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['content'][0]['text']
        else:
            return f"Error: API returned status code {response.status_code} - {response.text}"
            
    except Exception as e:
        return f"Error calling Claude API: {str(e)}"

def get_uncovered_techniques(covered_techniques: Dict, all_mitre_techniques: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Identify MITRE techniques that are not covered by current use cases.
    Only counts parent techniques (not sub-techniques with dots in ID).
    
    Returns:
        Tuple of (uncovered_techniques_list, total_parent_technique_count)
    """
    # Extract covered technique IDs (remove any formatting like "T1234 - Name")
    covered_ids = set()
    for tech_id in covered_techniques.keys():
        # Extract just the ID part if it contains " - "
        if ' - ' in str(tech_id):
            clean_id = str(tech_id).split(' - ')[0].strip()
        else:
            clean_id = str(tech_id).strip()
        covered_ids.add(clean_id)
    
    # Filter to only parent techniques (exclude sub-techniques)
    # Sub-techniques have format T####.### (with a dot)
    parent_techniques = []
    for tech in all_mitre_techniques:
        tech_id = tech.get('id', '')
        # Only include if:
        # 1. ID starts with 'T' 
        # 2. ID does not contain a dot (not a sub-technique)
        # 3. ID is not 'N/A'
        if tech_id.startswith('T') and '.' not in tech_id and tech_id != 'N/A':
            parent_techniques.append(tech)
    
    # Get set of all parent technique IDs
    all_parent_ids = {tech['id'] for tech in parent_techniques}
    
    # Find uncovered IDs
    uncovered_ids = all_parent_ids - covered_ids
    
    # Return full technique details for uncovered techniques
    uncovered = [tech for tech in parent_techniques if tech['id'] in uncovered_ids]
    
    return uncovered, len(parent_techniques)

def prioritize_gaps(uncovered_techniques: List[Dict], 
                    user_environment: Dict = None) -> pd.DataFrame:
    """
    Prioritize gaps based on multiple factors:
    - Tactic criticality (Initial Access, Execution, Persistence are high priority)
    - Technique prevalence (common techniques used by threat actors)
    
    Priority Score Calculation:
    - Tactic Score (60% weight): 6-10 based on tactic criticality
    - Prevalence Score (40% weight): 10 for high prevalence, 5 for medium
    - Final Score = (Tactic Score × 0.6) + (Prevalence Score × 0.4)
    - High Priority = Score >= 8.0
    """
    
    # Define priority scores for tactics based on security impact
    tactic_priority = {
        'initial-access': 10,      # Critical: Entry point for attackers
        'execution': 9,             # High: Running malicious code
        'persistence': 9,           # High: Maintaining foothold
        'privilege-escalation': 8,  # High: Gaining elevated access
        'defense-evasion': 8,       # High: Avoiding detection
        'credential-access': 8,     # High: Stealing credentials
        'discovery': 6,             # Medium: Reconnaissance
        'lateral-movement': 7,      # Medium-High: Spreading
        'collection': 6,            # Medium: Gathering data
        'command-and-control': 7,   # Medium-High: Communication
        'exfiltration': 8,          # High: Data theft
        'impact': 9                 # High: Disruption/destruction
    }
    
    # Common techniques based on real-world threat intelligence
    # These are frequently observed in the wild
    high_prevalence_techniques = {
        'T1059',  # Command and Scripting Interpreter
        'T1053',  # Scheduled Task/Job
        'T1055',  # Process Injection
        'T1003',  # OS Credential Dumping
        'T1078',  # Valid Accounts
        'T1082',  # System Information Discovery
        'T1083',  # File and Directory Discovery
        'T1021',  # Remote Services
        'T1070',  # Indicator Removal
        'T1105',  # Ingress Tool Transfer
        'T1027',  # Obfuscated Files or Information
        'T1204',  # User Execution
        'T1071',  # Application Layer Protocol
        'T1569',  # System Services
        'T1562'   # Impair Defenses
    }
    
    gap_data = []
    
    for tech in uncovered_techniques:
        # Calculate tactic score (use highest if multiple tactics)
        tactic_score = 5  # Default
        if tech.get('tactics_list'):
            tactic_score = max([tactic_priority.get(tactic, 5) 
                               for tactic in tech.get('tactics_list', [])])
        
        # Calculate prevalence score
        prevalence_score = 10 if tech['id'] in high_prevalence_techniques else 5
        
        # Combined priority score (weighted average)
        priority_score = (tactic_score * 0.6) + (prevalence_score * 0.4)
        
        gap_data.append({
            'Technique ID': tech['id'],
            'Technique Name': tech['name'],
            'Primary Tactic': tech.get('tactics_list', ['Unknown'])[0] if tech.get('tactics_list') else 'Unknown',
            'All Tactics': ', '.join(tech.get('tactics_list', [])),
            'Priority Score': round(priority_score, 2),
            'Prevalence': 'High' if tech['id'] in high_prevalence_techniques else 'Medium',
            'Description': tech.get('description', '')[:200] + '...',
            'URL': tech.get('url', '')
        })
    
    df = pd.DataFrame(gap_data)
    df = df.sort_values('Priority Score', ascending=False)
    
    return df

def generate_use_cases_with_claude(gap_df: pd.DataFrame, 
                                    api_key: str,
                                    top_n: int = 10) -> pd.DataFrame:
    """
    Use Claude API to generate intelligent use case recommendations for coverage gaps
    """
    
    if gap_df.empty or not api_key:
        return pd.DataFrame()
    
    suggestions = []
    
    # Focus on top priority gaps
    top_gaps = gap_df.head(top_n)
    
    # Create a batch prompt for efficiency
    techniques_info = []
    for _, gap in top_gaps.iterrows():
        techniques_info.append({
            'id': gap['Technique ID'],
            'name': gap['Technique Name'],
            'tactic': gap['Primary Tactic'],
            'description': gap['Description']
        })
    
    prompt = f"""You are a cybersecurity expert helping to create detection use cases for MITRE ATT&CK techniques that are currently not covered.

Below are {len(techniques_info)} high-priority techniques that need coverage:

{json.dumps(techniques_info, indent=2)}

For each technique, please provide:
1. A concise use case name (e.g., "Detect PowerShell Execution")
2. A detailed description of what to monitor and detect (2-3 sentences)
3. Recommended log sources to implement this detection (be specific)
4. Key indicators or patterns to look for (specific events, behaviors, or anomalies)

Format your response as a JSON array with this structure:
[
  {{
    "technique_id": "T1234",
    "technique_name": "Example Technique",
    "use_case_name": "Detect Example Technique",
    "description": "Detailed description of what to monitor...",
    "log_sources": ["Windows Event Logs", "EDR"],
    "indicators": ["Specific patterns or behaviors to detect"]
  }},
  ...
]

IMPORTANT: Return ONLY valid JSON, no other text. Ensure all quotes are properly escaped."""

    with st.spinner("Generating intelligent use case recommendations with Claude..."):
        response = call_claude_api(prompt, api_key)
        
        # Try to parse the JSON response
        try:
            # Clean the response - remove markdown code blocks if present
            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            
            recommendations = json.loads(cleaned_response)
            
            # Convert to DataFrame
            for i, rec in enumerate(recommendations):
                # Get the original gap info for priority score
                gap_row = top_gaps[top_gaps['Technique ID'] == rec.get('technique_id')]
                priority = gap_row.iloc[0]['Priority Score'] if not gap_row.empty else 5.0
                tactic = gap_row.iloc[0]['Primary Tactic'] if not gap_row.empty else 'Unknown'
                url = gap_row.iloc[0]['URL'] if not gap_row.empty else ''
                
                suggestions.append({
                    'Priority Rank': i + 1,
                    'Missing Technique ID': rec.get('technique_id', 'N/A'),
                    'Missing Technique Name': rec.get('technique_name', 'N/A'),
                    'Primary Tactic': tactic,
                    'Priority Score': priority,
                    'Suggested Use Case': rec.get('use_case_name', 'N/A'),
                    'Suggested Description': rec.get('description', 'N/A'),
                    'Recommended Log Source': ', '.join(rec.get('log_sources', [])),
                    'Key Indicators': ', '.join(rec.get('indicators', [])),
                    'MITRE URL': url
                })
            
            return pd.DataFrame(suggestions)
            
        except json.JSONDecodeError as e:
            st.error(f"Error parsing Claude API response: {str(e)}")
            st.error(f"Response received: {response[:500]}")
            return pd.DataFrame()

def render_gap_analysis_page(mitre_techniques):
    """
    Render the Gap Analysis page with Claude API-powered recommendations
    """
    st.markdown("# 🎯 Coverage Gap Analysis")
    
    if not st.session_state.mapping_complete or st.session_state.processed_data is None:
        st.info("Please complete the mapping process on the Home page first.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()
        return
    
    # API Key input in sidebar
    with st.sidebar:
        st.markdown("### Claude API Configuration")
        api_key = st.text_input(
            "Anthropic API Key",
            type="password",
            help="Enter your Anthropic API key to enable AI-powered recommendations"
        )
        
        if api_key:
            st.success("✓ API Key configured")
        else:
            st.warning("⚠ API Key required for AI features")
    
    df = st.session_state.processed_data
    covered_techniques = st.session_state.techniques_count
    
    # Get uncovered techniques with correct count
    with st.spinner("Analyzing coverage gaps..."):
        uncovered, total_parent_techniques = get_uncovered_techniques(covered_techniques, mitre_techniques)
        gap_df = prioritize_gaps(uncovered)
    
    # Display summary metrics
    st.markdown("### Coverage Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    covered_count = len(covered_techniques)
    gap_count = len(uncovered)
    coverage_pct = round((covered_count / total_parent_techniques) * 100, 1) if total_parent_techniques > 0 else 0
    
    with col1:
        st.metric("Total MITRE Techniques", total_parent_techniques, 
                 help="Enterprise ATT&CK parent techniques only (excluding sub-techniques)")
    with col2:
        st.metric("Covered Techniques", covered_count, 
                 delta=f"{coverage_pct}% coverage")
    with col3:
        st.metric("Coverage Gaps", gap_count, 
                 delta=f"{100-coverage_pct}% uncovered", delta_color="inverse")
    with col4:
        high_priority_gaps = len(gap_df[gap_df['Priority Score'] >= 8])
        st.metric("High Priority Gaps", high_priority_gaps,
                 help="Techniques with Priority Score >= 8.0")
    
    # Priority Score Explanation
    with st.expander("ℹ️ How Priority Score is Calculated"):
        st.markdown("""
        **Priority Score Formula:**
        - **Tactic Score** (60% weight): Based on security criticality
          - Critical (10): Initial Access, Impact
          - High (9): Execution, Persistence
          - High (8): Privilege Escalation, Defense Evasion, Credential Access, Exfiltration
          - Medium-High (7): Lateral Movement, Command & Control
          - Medium (6): Discovery, Collection
        
        - **Prevalence Score** (40% weight): Based on real-world threat intelligence
          - High (10): Frequently observed in the wild
          - Medium (5): Less commonly observed
        
        **Final Score** = (Tactic Score × 0.6) + (Prevalence Score × 0.4)
        
        **High Priority** = Score >= 8.0
        
        This means techniques are prioritized if they are either:
        - Part of critical tactics (Initial Access, Execution, Persistence, Impact), OR
        - Commonly used by threat actors in real-world attacks
        """)
    
    # Display prioritized gaps
    st.markdown("### 🔴 Top Priority Gaps")
    st.markdown("These techniques are not currently covered and are prioritized by security impact and real-world prevalence.")
    
    # Show top 20 gaps by default
    display_cols = ['Priority Score', 'Technique ID', 'Technique Name', 
                   'Primary Tactic', 'Prevalence']
    
    # Add filter for showing all or just high priority
    show_filter = st.radio(
        "Display:",
        options=["Show All Gaps", "High Priority Only (Score >= 8)"],
        horizontal=True
    )
    
    if show_filter == "High Priority Only (Score >= 8)":
        filtered_gaps = gap_df[gap_df['Priority Score'] >= 8]
    else:
        filtered_gaps = gap_df
    
    st.dataframe(filtered_gaps[display_cols], use_container_width=True)
    
    # AI-Powered Use Case Suggestions with Claude API
    st.markdown("---")
    st.markdown("### 🤖 AI-Generated Use Case Recommendations")
    st.markdown("Powered by Claude API - Get intelligent, context-aware recommendations for your coverage gaps")
    
    if not api_key:
        st.warning("⚠ Please enter your Anthropic API Key in the sidebar to enable AI-powered recommendations.")
    else:
        col1, col2 = st.columns([3, 1])
        with col1:
            num_recommendations = st.slider(
                "Number of recommendations to generate",
                min_value=5,
                max_value=20,
                value=10
            )
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            generate_button = st.button("Generate AI Recommendations", type="primary")
        
        if generate_button:
            suggestions_df = generate_use_cases_with_claude(
                gap_df,
                api_key,
                top_n=num_recommendations
            )
            
            if not suggestions_df.empty:
                st.session_state.gap_suggestions = suggestions_df
                st.success(f"✓ Generated {len(suggestions_df)} use case recommendations!")
            else:
                st.error("Failed to generate recommendations. Please check your API key and try again.")
    
    # Display suggestions if available
    if 'gap_suggestions' in st.session_state and not st.session_state.gap_suggestions.empty:
        suggestions_df = st.session_state.gap_suggestions
        
        # Display suggestions table
        st.markdown("#### Recommended Use Cases to Implement")
        
        display_suggestions = suggestions_df[[
            'Priority Rank', 'Missing Technique Name', 'Primary Tactic',
            'Suggested Use Case', 'Recommended Log Source', 'Priority Score'
        ]]
        
        st.dataframe(display_suggestions, use_container_width=True)
        
        # Detailed view
        st.markdown("#### Detailed Recommendation View")
        selected_suggestion = st.selectbox(
            "Select a recommendation to view details",
            options=suggestions_df['Suggested Use Case'].tolist()
        )
        
        if selected_suggestion:
            selected = suggestions_df[
                suggestions_df['Suggested Use Case'] == selected_suggestion
            ].iloc[0]
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Missing Technique**")
                st.info(f"{selected['Missing Technique ID']}: {selected['Missing Technique Name']}")
                
                st.markdown("**Suggested Use Case**")
                st.write(selected['Suggested Use Case'])
                
                st.markdown("**Description**")
                st.write(selected['Suggested Description'])
                
                if 'Key Indicators' in selected and selected['Key Indicators'] != 'N/A':
                    st.markdown("**Key Indicators to Monitor**")
                    st.write(selected['Key Indicators'])
            
            with col2:
                st.markdown("**Primary Tactic**")
                st.write(selected['Primary Tactic'])
                
                st.markdown("**Priority Score**")
                st.progress(selected['Priority Score'] / 10)
                st.write(f"{selected['Priority Score']} / 10")
                
                st.markdown("**Recommended Log Source**")
                st.write(selected['Recommended Log Source'])
                
                st.markdown("**MITRE ATT&CK Reference**")
                if selected['MITRE URL']:
                    st.markdown(f"[View on MITRE ATT&CK]({selected['MITRE URL']})")
        
        # Download options
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            st.download_button(
                "📥 Download Gap Analysis",
                gap_df.to_csv(index=False).encode('utf-8'),
                "coverage_gaps.csv",
                "text/csv"
            )
        
        with col2:
            st.download_button(
                "📥 Download Use Case Recommendations",
                suggestions_df.to_csv(index=False).encode('utf-8'),
                "recommended_use_cases.csv",
                "text/csv"
            )
