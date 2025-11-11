# gap_analysis.py - AI-Powered Coverage Gap Analysis

import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from typing import List, Dict, Tuple
import torch

def get_uncovered_techniques(covered_techniques: Dict, all_mitre_techniques: List[Dict]) -> List[Dict]:
    """
    Identify MITRE techniques that are not covered by current use cases
    """
    covered_ids = set(covered_techniques.keys())
    all_technique_ids = {tech['id'] for tech in all_mitre_techniques}
    
    uncovered_ids = all_technique_ids - covered_ids
    
    # Return full technique details for uncovered techniques
    uncovered = [tech for tech in all_mitre_techniques if tech['id'] in uncovered_ids]
    
    return uncovered

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

def generate_use_case_suggestions(gap_df: pd.DataFrame, 
                                   model,
                                   library_df: pd.DataFrame,
                                   library_embeddings: torch.Tensor,
                                   top_n: int = 10) -> pd.DataFrame:
    """
    Use AI to generate suggested use cases for gaps by finding similar 
    techniques in the library and adapting them
    """
    
    if library_df is None or library_embeddings is None or gap_df.empty:
        return pd.DataFrame()
    
    suggestions = []
    
    # Focus on top priority gaps
    top_gaps = gap_df.head(top_n)
    
    for _, gap in top_gaps.iterrows():
        # Use technique description to find similar use cases
        description = gap['Description']
        
        try:
            # Encode the gap description
            gap_embedding = model.encode(description, convert_to_tensor=True)
            
            # Find similar use cases in library
            if len(gap_embedding.shape) == 1:
                gap_embedding = gap_embedding.unsqueeze(0)
            
            # Normalize
            gap_embedding = gap_embedding / gap_embedding.norm(dim=1, keepdim=True)
            library_embeddings_norm = library_embeddings / library_embeddings.norm(dim=1, keepdim=True)
            
            # Calculate similarity
            similarities = torch.mm(gap_embedding, library_embeddings_norm.T)
            best_idx = similarities[0].argmax().item()
            similarity_score = similarities[0][best_idx].item()
            
            # Get the most similar library use case
            similar_use_case = library_df.iloc[best_idx]
            
            # Generate suggestion
            suggestions.append({
                'Priority Rank': len(suggestions) + 1,
                'Missing Technique ID': gap['Technique ID'],
                'Missing Technique Name': gap['Technique Name'],
                'Primary Tactic': gap['Primary Tactic'],
                'Priority Score': gap['Priority Score'],
                'Suggested Use Case': f"Detect {gap['Technique Name']}",
                'Suggested Description': f"Monitor and detect attempts to use {gap['Technique Name']}. "
                                        f"Similar to: {similar_use_case.get('Description', 'N/A')[:100]}...",
                'Recommended Log Source': similar_use_case.get('Log Source', 'Unknown'),
                'Reference Use Case': similar_use_case.get('Use Case Name', 'N/A'),
                'Similarity to Reference': round(similarity_score * 100, 2),
                'MITRE URL': gap['URL']
            })
            
        except Exception as e:
            print(f"Error generating suggestion for {gap['Technique ID']}: {e}")
            continue
    
    return pd.DataFrame(suggestions)

def recommend_log_sources(suggestions_df: pd.DataFrame, 
                         existing_log_sources: set) -> Dict:
    """
    Analyze recommended log sources and identify which ones need to be onboarded
    """
    
    if suggestions_df.empty:
        return {}
    
    # Extract recommended log sources
    recommended_sources = set()
    for sources in suggestions_df['Recommended Log Source']:
        if pd.notna(sources) and sources != 'Unknown':
            for source in str(sources).split(','):
                recommended_sources.add(source.strip())
    
    # Identify missing log sources
    missing_sources = recommended_sources - existing_log_sources
    existing_coverage = recommended_sources & existing_log_sources
    
    # Count how many use cases each log source would enable
    source_impact = {}
    for source in missing_sources:
        count = suggestions_df['Recommended Log Source'].str.contains(
            source, case=False, na=False
        ).sum()
        source_impact[source] = count
    
    return {
        'missing_sources': missing_sources,
        'existing_coverage': existing_coverage,
        'source_impact': source_impact,
        'total_recommended': len(recommended_sources)
    }

def render_gap_analysis_page(mitre_techniques):
    """
    Render the Gap Analysis page with AI-powered recommendations
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
    
    # Get uncovered techniques
    with st.spinner("Analyzing coverage gaps..."):
        uncovered = get_uncovered_techniques(covered_techniques, mitre_techniques)
        gap_df = prioritize_gaps(uncovered)
    
    # Display summary metrics
    st.markdown("### Coverage Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_techniques = len(mitre_techniques)
    covered_count = len(covered_techniques)
    gap_count = len(uncovered)
    coverage_pct = round((covered_count / total_techniques) * 100, 1)
    
    with col1:
        st.metric("Total MITRE Techniques", total_techniques)
    with col2:
        st.metric("Covered Techniques", covered_count, 
                 delta=f"{coverage_pct}% coverage")
    with col3:
        st.metric("Coverage Gaps", gap_count, 
                 delta=f"{100-coverage_pct}% uncovered", delta_color="inverse")
    with col4:
        high_priority_gaps = len(gap_df[gap_df['Priority Score'] >= 8])
        st.metric("High Priority Gaps", high_priority_gaps)
    
    # Visualize gap distribution by tactic
    st.markdown("### Gap Distribution by Tactic")
    
    tactic_gaps = gap_df['Primary Tactic'].value_counts().reset_index()
    tactic_gaps.columns = ['Tactic', 'Gap Count']
    
    fig_gaps = px.bar(
        tactic_gaps,
        x='Tactic',
        y='Gap Count',
        title="Number of Uncovered Techniques by Tactic",
        color='Gap Count',
        color_continuous_scale='Reds'
    )
    st.plotly_chart(fig_gaps, use_container_width=True)
    
    # Display prioritized gaps
    st.markdown("### 🔴 Top Priority Gaps")
    st.markdown("These techniques are not currently covered and should be prioritized based on prevalence and criticality.")
    
    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        min_priority = st.slider("Minimum Priority Score", 
                                min_value=float(gap_df['Priority Score'].min()),
                                max_value=float(gap_df['Priority Score'].max()),
                                value=7.0)
    with col2:
        selected_tactics = st.multiselect(
            "Filter by Tactic",
            options=sorted(gap_df['Primary Tactic'].unique()),
            default=[]
        )
    
    # Apply filters
    filtered_gaps = gap_df[gap_df['Priority Score'] >= min_priority]
    if selected_tactics:
        filtered_gaps = filtered_gaps[filtered_gaps['Primary Tactic'].isin(selected_tactics)]
    
    # Display filtered gaps
    display_cols = ['Priority Score', 'Technique ID', 'Technique Name', 
                   'Primary Tactic', 'Prevalence']
    st.dataframe(filtered_gaps[display_cols], use_container_width=True)
    
    # AI-Powered Use Case Suggestions
    st.markdown("---")
    st.markdown("### 🤖 AI-Generated Use Case Recommendations")
    st.markdown("Based on the coverage gaps, here are suggested use cases to implement:")
    
    if st.button("Generate AI Recommendations", type="primary"):
        with st.spinner("Generating intelligent recommendations..."):
            # Generate suggestions
            suggestions_df = generate_use_case_suggestions(
                filtered_gaps,
                st.session_state.model,
                st.session_state.library_data,
                st.session_state.library_embeddings,
                top_n=15
            )
            
            if not suggestions_df.empty:
                st.session_state.gap_suggestions = suggestions_df
                st.success(f"Generated {len(suggestions_df)} use case recommendations!")
            else:
                st.warning("Could not generate recommendations. Please check your library data.")
    
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
                
                st.markdown("**Reference Use Case**")
                st.write(f"{selected['Reference Use Case']} (Similarity: {selected['Similarity to Reference']}%)")
            
            with col2:
                st.markdown("**Primary Tactic**")
                st.write(selected['Primary Tactic'])
                
                st.markdown("**Priority Score**")
                st.progress(selected['Priority Score'] / 10)
                st.write(f"{selected['Priority Score']} / 10")
                
                st.markdown("**Recommended Log Source**")
                st.write(selected['Recommended Log Source'])
                
                st.markdown("**MITRE ATT&CK Reference**")
                st.markdown(f"[View on MITRE ATT&CK]({selected['MITRE URL']})")
        
        # Log Source Analysis
        st.markdown("---")
        st.markdown("### 📊 Log Source Onboarding Analysis")
        
        # Get existing log sources
        existing_sources = set()
        if 'Log Source' in df.columns:
            for source in df['Log Source']:
                if pd.notna(source) and source != 'N/A':
                    for s in str(source).split(','):
                        existing_sources.add(s.strip())
        
        # Analyze log source needs
        log_analysis = recommend_log_sources(suggestions_df, existing_sources)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Missing Log Sources")
            if log_analysis['missing_sources']:
                st.warning(f"You need {len(log_analysis['missing_sources'])} additional log sources")
                
                # Show impact of each source
                source_impact_df = pd.DataFrame([
                    {'Log Source': source, 'Use Cases Enabled': count}
                    for source, count in sorted(
                        log_analysis['source_impact'].items(),
                        key=lambda x: x[1],
                        reverse=True
                    )
                ])
                
                st.dataframe(source_impact_df, use_container_width=True)
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
