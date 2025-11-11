import pandas as pd
import streamlit as st

def get_suggested_use_cases(uploaded_df, library_df):
    """
    Find use cases from the library that match log sources in the uploaded data
    but aren't already present in the uploaded data.
    
    Returns a DataFrame with suggested use cases.
    """
    if uploaded_df is None or library_df is None or library_df.empty:
        return pd.DataFrame()
    
    # Step 1: Extract unique log sources from uploaded data
    user_log_sources = set()
    if 'Log Source' in uploaded_df.columns:
        # Handle multi-value log sources (comma separated)
        for log_source in uploaded_df['Log Source'].fillna('').astype(str):
            if log_source and log_source != 'N/A':
                for source in log_source.split(','):
                    user_log_sources.add(source.strip())
    
    # Filter out empty or N/A sources
    user_log_sources = {src for src in user_log_sources if src and src != 'N/A'}
    
    if not user_log_sources:
        return pd.DataFrame()  # No valid log sources found
    
    # Step 2: Find matching use cases in the library based on log sources
    matching_use_cases = []
    
    # Get set of existing use case descriptions for deduplication
    existing_descriptions = set()
    if 'Description' in uploaded_df.columns:
        existing_descriptions = set(uploaded_df['Description'].fillna('').astype(str).str.lower())
    
    # For each library entry, check if its log source matches any user log source
    for _, lib_row in library_df.iterrows():
        lib_log_source = str(lib_row.get('Log Source', ''))
        lib_description = str(lib_row.get('Description', '')).lower()
        
        # Check if any user log source matches this library entry's log source
        if any(user_source.lower() in lib_log_source.lower() for user_source in user_log_sources):
            # Check if this use case is already in the user's data (by description)
            if lib_description not in existing_descriptions:
                matching_use_cases.append(lib_row)
    
    # If we have matches, convert to DataFrame
    if matching_use_cases:
        suggestions_df = pd.DataFrame(matching_use_cases)
        
        # Add a relevance score column based on exact log source match
        suggestions_df['Relevance'] = suggestions_df.apply(
            lambda row: sum(1 for src in user_log_sources 
                          if src.lower() in str(row.get('Log Source', '')).lower()),
            axis=1
        )
        
        # Sort by relevance (highest first)
        suggestions_df = suggestions_df.sort_values('Relevance', ascending=False)
        
        # Include only relevant columns and rename for clarity
        needed_columns = ['Use Case Name', 'Description', 'Log Source', 
                          'Mapped MITRE Tactic(s)', 'Mapped MITRE Technique(s)',
                          'Reference Resource(s)', 'Search', 'Relevance']
        
        # Filter columns that exist
        actual_columns = [col for col in needed_columns if col in suggestions_df.columns]
        return suggestions_df[actual_columns]
    
    return pd.DataFrame()  # No suggestions found

def render_suggestions_page():
    st.markdown("# 🔍 Suggested Use Cases")
    
    if st.session_state.file_uploaded:
        if st.session_state.library_data is not None and not st.session_state.library_data.empty:
            
            uploaded_df = None
            if 'processed_data' in st.session_state and st.session_state.processed_data is not None:
                uploaded_df = st.session_state.processed_data
            else:
                # Try to get the original uploaded data if processing hasn't happened yet
                try:
                    uploaded_file = st.session_state.get('_uploaded_file')
                    if uploaded_file:
                        uploaded_df = pd.read_csv(uploaded_file)
                except:
                    pass
            
            if uploaded_df is None:
                st.info("Please upload your data file on the Home page first.")
                return
                
            # Get suggestions based on log sources
            with st.spinner("Finding suggested use cases based on log sources..."):
                log_source_suggestions = get_suggested_use_cases(
                    uploaded_df, 
                    st.session_state.library_data
                )
            
            # Display suggestions
            if not log_source_suggestions.empty:
                st.success(f"Found {len(log_source_suggestions)} suggested use cases based on your log sources!")
                
                # Format the dataframe for display
                display_df = log_source_suggestions.copy()
                if 'Relevance' in display_df.columns:
                    display_df['Relevance Score'] = display_df['Relevance'].apply(lambda x: f"{x:.0f} ⭐")
                    display_df = display_df.drop('Relevance', axis=1)
                
                st.dataframe(display_df, use_container_width=True)
                
                # Add a detailed view for each suggestion
                st.markdown("### Detailed View")
                selected_suggestion = st.selectbox(
                    "Select a use case to view details",
                    options=display_df['Use Case Name'].tolist(),
                    index=0
                )
                
                if selected_suggestion:
                    selected_row = display_df[display_df['Use Case Name'] == selected_suggestion].iloc[0]
                    
                    # Create columns for the detailed view
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        st.markdown("#### Use Case Details")
                        st.markdown(f"**Name:** {selected_row.get('Use Case Name', 'N/A')}")
                        st.markdown(f"**Log Source:** {selected_row.get('Log Source', 'N/A')}")
                        st.markdown(f"**Description:**")
                        st.markdown(f"{selected_row.get('Description', 'No description available')}")
                    
                    with col2:
                        st.markdown("#### MITRE ATT&CK Mapping")
                        st.markdown(f"**Tactic(s):** {selected_row.get('Mapped MITRE Tactic(s)', 'N/A')}")
                        st.markdown(f"**Technique(s):** {selected_row.get('Mapped MITRE Technique(s)', 'N/A')}")
                        
                        # Display reference resources if available
                        if 'Reference Resource(s)' in selected_row and selected_row['Reference Resource(s)'] != 'N/A':
                            st.markdown("#### Reference Resources")
                            st.markdown(f"{selected_row['Reference Resource(s)']}")
                    
                    # Display search query in a separate section
                    if 'Search' in selected_row and selected_row['Search'] != 'N/A' and not pd.isna(selected_row['Search']):
                        st.markdown("### Search Query")
                        st.code(selected_row['Search'], language="sql")
                
                # Download option
                st.download_button(
                    "Download Suggested Use Cases as CSV",
                    log_source_suggestions.to_csv(index=False).encode('utf-8'),
                    "suggested_use_cases.csv",
                    "text/csv"
                )
            else:
                st.info("No additional use cases found based on your log sources.")
        else:
            st.warning("Library data is not available. Cannot provide suggestions without a reference library.")
    else:
        st.info("Please upload your security use cases CSV file on the Home page first.")
        
        # Add a button to navigate back to home
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()
