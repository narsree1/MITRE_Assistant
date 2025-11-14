# gap_analysis.py - Library-Based Coverage Gap Analysis

import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Tuple
import torch

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

def find_library_matches_for_gaps(gap_df: pd.DataFrame, 
                                   library_df: pd.DataFrame,
                                   mitre_techniques: List[Dict]) -> pd.DataFrame:
    """
    Find library use cases that match the uncovered techniques in gap analysis.
    Returns a DataFrame with library recommendations sorted by priority score.
    """
    if gap_df.empty or library_df is None or library_df.empty:
        return pd.DataFrame()
    
    recommendations = []
    
    # Create a mapping of technique names to IDs for easier matching
    technique_name_to_id = {tech['name']: tech['id'] for tech in mitre_techniques}
    technique_id_to_info = {tech['id']: tech for tech in mitre_techniques}
    
    # For each gap (uncovered technique)
    for _, gap_row in gap_df.iterrows():
        gap_technique_id = gap_row['Technique ID']
        gap_technique_name = gap_row['Technique Name']
        
        # Search library for use cases that map to this technique
        for _, lib_row in library_df.iterrows():
            lib_techniques = str(lib_row.get('Mapped MITRE Technique(s)', ''))
            
            if pd.isna(lib_techniques) or lib_techniques == 'N/A':
                continue
            
            # Check if this library entry covers the gap technique
            # Handle both "T1234 - Name" and "Name" formats
            technique_matched = False
            
            # Split comma-separated techniques
            for lib_tech in lib_techniques.split(','):
                lib_tech = lib_tech.strip()
                
                # Extract technique ID if present
                if ' - ' in lib_tech and lib_tech.startswith('T'):
                    lib_tech_id = lib_tech.split(' - ')[0].strip()
                else:
                    # Try to find ID by name
                    lib_tech_id = technique_name_to_id.get(lib_tech, lib_tech)
                
                # Check if it matches the gap technique
                if lib_tech_id == gap_technique_id or lib_tech == gap_technique_name:
                    technique_matched = True
                    break
            
            if technique_matched:
                # Extract key information from description for "Key Indicators"
                description = str(lib_row.get('Description', ''))
                
                # Try to extract key indicators (look for specific patterns)
                key_indicators = []
                if 'EventCode' in description or 'Event ID' in description:
                    key_indicators.append("Specific Event IDs")
                if 'error' in description.lower() or 'failed' in description.lower():
                    key_indicators.append("Error patterns")
                if 'unusual' in description.lower() or 'anomal' in description.lower():
                    key_indicators.append("Anomalous behavior")
                if 'multiple' in description.lower() or 'excessive' in description.lower():
                    key_indicators.append("Volume-based detection")
                
                if not key_indicators:
                    key_indicators = ["See description for details"]
                
                recommendations.append({
                    'Priority Score': gap_row['Priority Score'],
                    'Missing Technique ID': gap_technique_id,
                    'Missing Technique Name': gap_technique_name,
                    'Primary Tactic': gap_row['Primary Tactic'],
                    'Suggested Use Case': lib_row.get('Use Case Name', 'N/A'),
                    'Suggested Description': lib_row.get('Description', 'N/A'),
                    'Recommended Log Source': lib_row.get('Log Source', 'N/A'),
                    'Key Indicators': ', '.join(key_indicators),
                    'Reference Resources': lib_row.get('Reference Resource(s)', 'N/A'),
                    'Search Query': lib_row.get('Search', 'N/A'),
                    'MITRE URL': gap_row['URL']
                })
    
    if recommendations:
        recommendations_df = pd.DataFrame(recommendations)
        # Sort by priority score (highest first)
        recommendations_df = recommendations_df.sort_values('Priority Score', ascending=False)
        # Add priority rank
        recommendations_df.insert(0, 'Priority Rank', range(1, len(recommendations_df) + 1))
        return recommendations_df
    
    return pd.DataFrame()

def render_gap_analysis_page(mitre_techniques):
    """
    Render the Gap Analysis page with library-based recommendations
    """
    st.markdown("# 🎯 Coverage Gap Analysis")
    
    if not st.session_state.mapping_complete or st.session_state.processed_data is None:
        st.info("Please complete the mapping process on the Home page first.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()
        return
    
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
    
    # Library-Based Use Case Recommendations
    st.markdown("---")
    st.markdown("### 📚 Library-Based Use Case Recommendations")
    st.markdown("Use cases from the library that can help address your coverage gaps")
    
    # Check if library data is available
    if st.session_state.library_data is None or st.session_state.library_data.empty:
        st.warning("⚠ No library data available. Please ensure library.csv is loaded.")
    else:
        # Find library matches for gaps
        with st.spinner("Finding library use cases that match your coverage gaps..."):
            library_recommendations = find_library_matches_for_gaps(
                gap_df,
                st.session_state.library_data,
                mitre_techniques
            )
        
        if not library_recommendations.empty:
            # Store in session state
            st.session_state.gap_suggestions = library_recommendations
            
            st.success(f"✓ Found {len(library_recommendations)} use cases from the library that can address your gaps!")
            
            # Display recommendations table
            st.markdown("#### Recommended Use Cases to Implement")
            
            display_recommendations = library_recommendations[[
                'Priority Rank', 'Priority Score', 'Missing Technique Name', 
                'Primary Tactic', 'Suggested Use Case', 'Recommended Log Source'
            ]]
            
            st.dataframe(display_recommendations, use_container_width=True)
            
            # Detailed Recommendation View
            st.markdown("---")
            st.markdown("#### Detailed Recommendation View")
            
            selected_suggestion = st.selectbox(
                "Select a recommendation to view details",
                options=library_recommendations['Suggested Use Case'].tolist()
            )
            
            if selected_suggestion:
                selected = library_recommendations[
                    library_recommendations['Suggested Use Case'] == selected_suggestion
                ].iloc[0]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**Missing Technique**")
                    st.info(f"{selected['Missing Technique ID']}: {selected['Missing Technique Name']}")
                    
                    st.markdown("**Primary Tactic**")
                    st.write(selected['Primary Tactic'])
                    
                    st.markdown("**Suggested Use Case**")
                    st.write(selected['Suggested Use Case'])
                    
                    st.markdown("**Description**")
                    st.write(selected['Suggested Description'])
                
                with col2:
                    st.markdown("**Priority Score**")
                    st.progress(selected['Priority Score'] / 10)
                    st.write(f"{selected['Priority Score']} / 10")
                    
                    st.markdown("**Recommended Log Source**")
                    st.write(selected['Recommended Log Source'])
                    
                    st.markdown("**Key Indicators to Monitor**")
                    st.write(selected['Key Indicators'])
                    
                    st.markdown("**MITRE ATT&CK Reference**")
                    if selected['MITRE URL']:
                        st.markdown(f"[View on MITRE ATT&CK]({selected['MITRE URL']})")
                
                # Display search query if available
                if 'Search Query' in selected and selected['Search Query'] != 'N/A' and not pd.isna(selected['Search Query']):
                    st.markdown("---")
                    st.markdown("**Search Query**")
                    st.code(selected['Search Query'], language="sql")
                
                # Display reference resources if available
                if 'Reference Resources' in selected and selected['Reference Resources'] != 'N/A' and not pd.isna(selected['Reference Resources']):
                    st.markdown("**Reference Resources**")
                    st.info(selected['Reference Resources'])
            
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
                    library_recommendations.to_csv(index=False).encode('utf-8'),
                    "recommended_use_cases.csv",
                    "text/csv"
                )
        else:
            st.info("No library use cases found that match your coverage gaps. Consider reviewing the library or adding new use cases.")
            
            # Still offer download of gap analysis
            st.download_button(
                "📥 Download Gap Analysis",
                gap_df.to_csv(index=False).encode('utf-8'),
                "coverage_gaps.csv",
                "text/csv"
            )
