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
    Identify MITRE techniques that are not covered by current use cases
    Only count parent techniques (not sub-techniques with dots in ID)
    Returns tuple of (uncovered_techniques, total_parent_technique_count)
    """
    covered_ids = set(covered_techniques.keys())
    
    # Filter to only parent techniques (exclude sub-techniques)
    parent_techniques = [tech for tech in all_mitre_techniques if '.' not in tech['id']]
    all_technique_ids = {tech['id'] for tech in parent_techniques}
    
    uncovered_ids = all_technique_ids - covered_ids
    
    # Return full technique details for uncovered techniques
    uncovered = [tech for tech in parent_techniques if tech['id'] in uncovered_ids]
    
    return uncovered, len(parent_techniques)

def prioritize_gaps(uncovered_techniques: List[Dict], 
                    user_environment: Dict = None) -> pd.DataFrame:
    """
    Prioritize gaps based on multiple factors:
    - Tactic criticality (Initial Access, Execution, Persistence are high priority)
    - Technique prevalence (common techniques used by threat actors)
    - Environmental relevance
    """
    
    # Define priority scores for tactics
    tactic_priority = {
        'initial-access': 10,
        'execution': 9,
        'persistence': 9,
        'privilege-escalation': 8,
        'defense-evasion': 8,
        'credential-access': 8,
        'discovery': 6,
        'lateral-movement': 7,
        'collection': 6,
        'command-and-control': 7,
        'exfiltration': 8,
        'impact': 9
    }
    
    # Common techniques based on ATT&CK statistics (simplified)
    high_prevalence_techniques = {
        'T1059', 'T1053', 'T1055', 'T1003', 'T1078', 'T1082', 
        'T1083', 'T1021', 'T1070', 'T1105', 'T1027', 'T1204'
    }
    
    gap_data = []
    
    for tech in uncovered_techniques:
        # Calculate priority score
        tactic_score = max([tactic_priority.get(tactic, 5) 
                           for tactic in tech.get('tactics_list', [])])
        
        prevalence_score = 10 if tech['id'] in high_prevalence_techniques else 5
        
        # Combined priority score
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
2. A detailed description of what to monitor and detect
3. Recommended log sources to implement this detection
4. Any specific indicators or patterns to look for

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
                url = gap_row.iloc[0]['URL'] if not gap_row.empty else ''
                
                suggestions.append({
                    'Priority Rank': i + 1,
                    'Missing Technique ID': rec.get('technique_id', 'N/A'),
                    'Missing Technique Name': rec.get('technique_name', 'N/A'),
                    'Primary Tactic': rec.get('technique_id', 'N/A').split('-')[0] if '-' in rec.get('technique_id', '') else 'Unknown',
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

def generate_log_sources_with_claude(suggestions_df: pd.DataFrame,
                                     existing_log_sources: set,
                                     api_key: str) -> Dict:
    """
    Use Claude API to analyze and recommend log sources needed for coverage
    """
    
    if suggestions_df.empty or not api_key:
        return {
            'missing_sources': set(),
            'existing_coverage': set(),
            'source_analysis': [],
            'total_recommended': 0
        }
    
    # Extract recommended log sources
    recommended_sources = set()
    for sources in suggestions_df['Recommended Log Source']:
        if pd.notna(sources) and sources != 'N/A':
            for source in str(sources).split(','):
                recommended_sources.add(source.strip())
    
    # Identify missing log sources
    missing_sources = recommended_sources - existing_log_sources
    existing_coverage = recommended_sources & existing_log_sources
    
    if not missing_sources:
        return {
            'missing_sources': missing_sources,
            'existing_coverage': existing_coverage,
            'source_analysis': [],
            'total_recommended': len(recommended_sources)
        }
    
    # Use Claude to provide detailed analysis of missing log sources
    prompt = f"""You are a cybersecurity infrastructure expert. Analyze the following missing log sources and provide recommendations.

Currently Available Log Sources:
{json.dumps(list(existing_log_sources), indent=2)}

Missing Log Sources Needed:
{json.dumps(list(missing_sources), indent=2)}

For each missing log source, provide:
1. Priority (High/Medium/Low) - based on security value
2. Implementation difficulty (Easy/Medium/Hard)
3. Number of use cases it would enable (count from the list below)
4. Brief implementation guidance (1-2 sentences)
5. Estimated cost (Low/Medium/High)

Use cases that need these sources:
{suggestions_df[['Suggested Use Case', 'Recommended Log Source']].to_dict('records')}

Format your response as a JSON array:
[
  {{
    "log_source": "Source Name",
    "priority": "High/Medium/Low",
    "difficulty": "Easy/Medium/Hard",
    "use_cases_enabled": 5,
    "implementation_guidance": "Brief guidance...",
    "estimated_cost": "Low/Medium/High"
  }},
  ...
]

IMPORTANT: Return ONLY valid JSON, no other text."""

    with st.spinner("Analyzing log source requirements with Claude..."):
        response = call_claude_api(prompt, api_key)
        
        try:
            # Clean the response
            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            
            analysis = json.loads(cleaned_response)
            
            return {
                'missing_sources': missing_sources,
                'existing_coverage': existing_coverage,
                'source_analysis': analysis,
                'total_recommended': len(recommended_sources)
            }
            
        except json.JSONDecodeError as e:
            st.error(f"Error parsing Claude API response for log sources: {str(e)}")
            # Return basic analysis without Claude insights
            return {
                'missing_sources': missing_sources,
                'existing_coverage': existing_coverage,
                'source_analysis': [],
                'total_recommended': len(recommended_sources)
            }

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
    coverage_pct = round((covered_count / total_parent_techniques) * 100, 1)
    
    with col1:
        st.metric("Total MITRE Techniques", total_parent_techniques, 
                 help="Parent techniques only (excluding sub-techniques)")
    with col2:
        st.metric("Covered Techniques", covered_count, 
                 delta=f"{coverage_pct}% coverage")
    with col3:
        st.metric("Coverage Gaps", gap_count, 
                 delta=f"{100-coverage_pct}% uncovered", delta_color="inverse")
    with col4:
        high_priority_gaps = len(gap_df[gap_df['Priority Score'] >= 8])
        st.metric("High Priority Gaps", high_priority_gaps)
    
    # Display prioritized gaps (removed filters)
    st.markdown("### 🔴 Top Priority Gaps")
    st.markdown("These techniques are not currently covered and should be prioritized based on prevalence and criticality.")
    
    # Display top gaps without filters
    display_cols = ['Priority Score', 'Technique ID', 'Technique Name', 
                   'Primary Tactic', 'Prevalence']
    st.dataframe(gap_df[display_cols], use_container_width=True)
    
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
        
        # Log Source Analysis with Claude API
        st.markdown("---")
        st.markdown("### 📊 Log Source Onboarding Analysis")
        st.markdown("Powered by Claude API - Get intelligent recommendations for log source prioritization")
        
        if not api_key:
            st.warning("⚠ Please enter your Anthropic API Key in the sidebar to enable log source analysis.")
        else:
            if st.button("Analyze Log Source Requirements", type="primary"):
                # Get existing log sources
                existing_sources = set()
                if 'Log Source' in df.columns:
                    for source in df['Log Source']:
                        if pd.notna(source) and source != 'N/A':
                            for s in str(source).split(','):
                                existing_sources.add(s.strip())
                
                # Analyze log source needs with Claude
                log_analysis = generate_log_sources_with_claude(
                    suggestions_df,
                    existing_sources,
                    api_key
                )
                
                st.session_state.log_analysis = log_analysis
                st.success("✓ Log source analysis complete!")
            
            # Display log analysis if available
            if 'log_analysis' in st.session_state:
                log_analysis = st.session_state.log_analysis
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### Missing Log Sources")
                    if log_analysis['missing_sources']:
                        st.warning(f"You need {len(log_analysis['missing_sources'])} additional log sources")
                        
                        # Show Claude's detailed analysis
                        if log_analysis['source_analysis']:
                            analysis_df = pd.DataFrame(log_analysis['source_analysis'])
                            
                            # Reorder columns for better display
                            column_order = ['log_source', 'priority', 'use_cases_enabled', 
                                          'difficulty', 'estimated_cost', 'implementation_guidance']
                            analysis_df = analysis_df[[col for col in column_order if col in analysis_df.columns]]
                            
                            # Rename columns for display
                            analysis_df = analysis_df.rename(columns={
                                'log_source': 'Log Source',
                                'priority': 'Priority',
                                'use_cases_enabled': 'Use Cases Enabled',
                                'difficulty': 'Implementation',
                                'estimated_cost': 'Est. Cost',
                                'implementation_guidance': 'Implementation Guidance'
                            })
                            
                            st.dataframe(analysis_df, use_container_width=True)
                        else:
                            # Fallback to simple list if Claude analysis failed
                            for source in sorted(log_analysis['missing_sources']):
                                st.write(f"❌ {source}")
                    else:
                        st.success("All recommended log sources are already onboarded!")
                
                with col2:
                    st.markdown("#### Existing Coverage")
                    st.info(f"{len(log_analysis['existing_coverage'])} recommended sources already available")
                    if log_analysis['existing_coverage']:
                        for source in sorted(log_analysis['existing_coverage']):
                            st.write(f"✅ {source}")
        
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
