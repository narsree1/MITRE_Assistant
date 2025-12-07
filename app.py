import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import torch
import numpy as np
import json
import datetime
import uuid
import plotly.graph_objects as go
import plotly.express as px
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
import time
import os
import hashlib
from typing import List, Dict, Tuple, Any, Optional
from gap_analysis import render_gap_analysis_page
from analytics import render_analytics_page

# App configuration
st.set_page_config(
    page_title="MITRE ATT&CK Mapping Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# BACKEND API KEY CONFIGURATION
# Set your permanent API key here if you want the app to always use it
# Otherwise, leave as None and users will enter it in the UI
# ============================================================================
BACKEND_API_KEY = None  # Change to "sk-ant-api03-..." for permanent backend key

# Define fallback similarity search functions
def cosine_similarity_search(query_embedding, reference_embeddings):
    """Fallback similarity search using PyTorch tensors"""
    if not isinstance(query_embedding, torch.Tensor):
        query_embedding = torch.tensor(query_embedding)
    if not isinstance(reference_embeddings, torch.Tensor):
        reference_embeddings = torch.tensor(reference_embeddings)
    
    if len(query_embedding.shape) == 1:
        query_embedding = query_embedding.unsqueeze(0)
    
    query_embedding = query_embedding / query_embedding.norm(dim=1, keepdim=True)
    reference_embeddings = reference_embeddings / reference_embeddings.norm(dim=1, keepdim=True)
    
    similarities = torch.mm(query_embedding, reference_embeddings.T)
    
    best_idx = similarities[0].argmax().item()
    best_score = similarities[0][best_idx].item()
    
    return best_score, best_idx

def batch_similarity_search(query_embeddings, reference_embeddings):
    """Batch similarity search using PyTorch tensors"""
    if not isinstance(query_embeddings, torch.Tensor):
        query_embeddings = torch.tensor(query_embeddings)
    if not isinstance(reference_embeddings, torch.Tensor):
        reference_embeddings = torch.tensor(reference_embeddings)
    
    query_embeddings = query_embeddings / query_embeddings.norm(dim=1, keepdim=True)
    reference_embeddings = reference_embeddings / reference_embeddings.norm(dim=1, keepdim=True)
    
    similarities = torch.mm(query_embeddings, reference_embeddings.T)
    
    best_scores, best_indices = similarities.max(dim=1)
    
    return best_scores.tolist(), best_indices.tolist()

# Custom CSS
st.markdown("""
<style>
    :root {
        --primary: #0d6efd;
        --secondary: #6c757d;
        --success: #198754;
        --danger: #dc3545;
        --warning: #ffc107;
        --info: #0dcaf0;
        --background: #f8f9fa;
        --card-bg: #ffffff;
        --text: #212529;
    }
    
    .main {
        background-color: var(--background);
        padding: 1.5rem;
    }
    
    .card {
        background-color: var(--card-bg);
        border-radius: 10px;
        box-shadow: 0 3px 5px rgba(0, 0, 0, 0.1);
        padding: 15px;
        margin-bottom: 15px;
    }
    
    .stButton button {
        border-radius: 6px;
        font-weight: 500;
        transition: all 0.3s ease;
    }
    
    h1 {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-weight: 600;
        font-size: 1.8rem;
    }
    
    h2 {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-weight: 600;
        font-size: 1.4rem;
    }
    
    h3 {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-weight: 600;
        font-size: 1.2rem;
    }
    
    .stMarkdown, p, div, span, .stText {
        font-size: 0.9rem;
    }
    
    .metric-card {
        background-color: var(--card-bg);
        border-radius: 10px;
        box-shadow: 0 3px 5px rgba(0, 0, 0, 0.1);
        padding: 12px;
        text-align: center;
        transition: transform 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-3px);
    }
    
    .metric-value {
        font-size: 22px;
        font-weight: 700;
        color: var(--primary);
    }
    
    .metric-label {
        font-size: 12px;
        color: var(--secondary);
    }
    
    .dataframe {
        border-radius: 6px;
        overflow: hidden;
        font-size: 0.85rem;
    }
    
    .sidebar .stMarkdown {
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'page' not in st.session_state:
    st.session_state.page = "home"
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'techniques_count' not in st.session_state:
    st.session_state.techniques_count = {}
if 'file_uploaded' not in st.session_state:
    st.session_state.file_uploaded = False
if 'mapping_complete' not in st.session_state:
    st.session_state.mapping_complete = False
if 'library_data' not in st.session_state:
    st.session_state.library_data = None
if 'library_embeddings' not in st.session_state:
    st.session_state.library_embeddings = None
if 'mitre_embeddings' not in st.session_state:
    st.session_state.mitre_embeddings = None
if '_uploaded_file' not in st.session_state:
    st.session_state._uploaded_file = None
if 'claude_cache' not in st.session_state:
    st.session_state.claude_cache = {}

def get_suggested_use_cases(uploaded_df, library_df):
    """Find use cases from library matching log sources"""
    if uploaded_df is None or library_df is None or library_df.empty:
        return pd.DataFrame()
    
    user_log_sources = set()
    if 'Log Source' in uploaded_df.columns:
        for log_source in uploaded_df['Log Source'].fillna('').astype(str):
            if log_source and log_source != 'N/A':
                for source in log_source.split(','):
                    user_log_sources.add(source.strip())
    
    user_log_sources = {src for src in user_log_sources if src and src != 'N/A'}
    
    if not user_log_sources:
        return pd.DataFrame()
    
    matching_use_cases = []
    existing_descriptions = set()
    if 'Description' in uploaded_df.columns:
        existing_descriptions = set(uploaded_df['Description'].fillna('').astype(str).str.lower())
    
    for _, lib_row in library_df.iterrows():
        lib_log_source = str(lib_row.get('Log Source', ''))
        lib_description = str(lib_row.get('Description', '')).lower()
        
        if any(user_source.lower() in lib_log_source.lower() for user_source in user_log_sources):
            if lib_description not in existing_descriptions:
                matching_use_cases.append(lib_row)
    
    if matching_use_cases:
        suggestions_df = pd.DataFrame(matching_use_cases)
        suggestions_df['Relevance'] = suggestions_df.apply(
            lambda row: sum(1 for src in user_log_sources 
                          if src.lower() in str(row.get('Log Source', '')).lower()),
            axis=1
        )
        suggestions_df = suggestions_df.sort_values('Relevance', ascending=False)
        
        needed_columns = ['Use Case Name', 'Description', 'Log Source', 
                          'Mapped MITRE Tactic(s)', 'Mapped MITRE Technique(s)',
                          'Reference Resource(s)', 'Search', 'Relevance']
        actual_columns = [col for col in needed_columns if col in suggestions_df.columns]
        return suggestions_df[actual_columns]
    
    return pd.DataFrame()

def render_suggestions_page():
    """Render suggestions page"""
    st.markdown("# 🔍 Suggested Use Cases")
    
    if st.session_state.file_uploaded:
        if st.session_state.library_data is not None and not st.session_state.library_data.empty:
            uploaded_df = None
            if 'processed_data' in st.session_state and st.session_state.processed_data is not None:
                uploaded_df = st.session_state.processed_data
            else:
                try:
                    uploaded_file = st.session_state.get('_uploaded_file')
                    if uploaded_file:
                        uploaded_df = pd.read_csv(uploaded_file)
                except:
                    pass
            
            if uploaded_df is None:
                st.info("Please upload your data file on the Home page first.")
                return
                
            with st.spinner("Finding suggested use cases..."):
                log_source_suggestions = get_suggested_use_cases(uploaded_df, st.session_state.library_data)
            
            if not log_source_suggestions.empty:
                st.success(f"Found {len(log_source_suggestions)} suggested use cases!")
                
                display_df = log_source_suggestions.copy()
                if 'Relevance' in display_df.columns:
                    display_df['Relevance Score'] = display_df['Relevance'].apply(lambda x: f"{x:.0f} ⭐")
                    display_df = display_df.drop('Relevance', axis=1)
                
                st.dataframe(display_df, use_container_width=True)
                
                st.markdown("### Detailed View")
                selected_suggestion = st.selectbox(
                    "Select a use case to view details",
                    options=display_df['Use Case Name'].tolist(),
                    index=0
                )
                
                if selected_suggestion:
                    selected_row = display_df[display_df['Use Case Name'] == selected_suggestion].iloc[0]
                    
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        st.markdown("#### Use Case Details")
                        st.markdown(f"**Name:** {selected_row.get('Use Case Name', 'N/A')}")
                        st.markdown(f"**Log Source:** {selected_row.get('Log Source', 'N/A')}")
                        st.markdown(f"**Description:** {selected_row.get('Description', 'N/A')}")
                    
                    with col2:
                        st.markdown("#### MITRE ATT&CK Mapping")
                        st.markdown(f"**Tactic(s):** {selected_row.get('Mapped MITRE Tactic(s)', 'N/A')}")
                        st.markdown(f"**Technique(s):** {selected_row.get('Mapped MITRE Technique(s)', 'N/A')}")
                        
                        if 'Reference Resource(s)' in selected_row and selected_row['Reference Resource(s)'] != 'N/A':
                            st.markdown("#### Reference Resources")
                            st.markdown(f"{selected_row['Reference Resource(s)']}")
                    
                    if 'Search' in selected_row and selected_row['Search'] != 'N/A' and not pd.isna(selected_row['Search']):
                        st.markdown("### Search Query")
                        st.code(selected_row['Search'], language="sql")
                
                st.download_button(
                    "Download Suggested Use Cases as CSV",
                    log_source_suggestions.to_csv(index=False).encode('utf-8'),
                    "suggested_use_cases.csv",
                    "text/csv"
                )
            else:
                st.info("No additional use cases found.")
        else:
            st.warning("Library data is not available.")
    else:
        st.info("Please upload your security use cases CSV file on the Home page first.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()

@st.cache_resource
def load_model():
    """Load embedding model"""
    try:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        model = SentenceTransformer('all-mpnet-base-v2')
        model = model.to(device)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

@st.cache_data
def load_mitre_data():
    """Load MITRE ATT&CK data - only active parent techniques"""
    try:
        response = requests.get(
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
            timeout=30
        )
        response.raise_for_status()
        attack_data = response.json()
        
        techniques = []
        tactic_mapping = {}
        tactics_list = []

        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id
                tactics_list.append(tactic_name)

        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                if obj.get('revoked', False):
                    continue
                if obj.get('x_mitre_deprecated', False):
                    continue
                
                external_refs = obj.get('external_references', [])
                if not external_refs:
                    continue
                
                tech_id = external_refs[0].get('external_id', 'N/A')
                
                if not tech_id or tech_id == 'N/A':
                    continue
                if '.' in tech_id:
                    continue
                if not tech_id.startswith('T'):
                    continue
                
                techniques.append({
                    'id': tech_id,
                    'name': obj.get('name', 'N/A'),
                    'description': obj.get('description', ''),
                    'tactic': ', '.join([phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]),
                    'tactics_list': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                    'url': external_refs[0].get('url', '')
                })
        
        return techniques, tactic_mapping, tactics_list
        
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], {}, []

@st.cache_resource
def get_mitre_embeddings(_model, techniques):
    """Compute MITRE technique embeddings"""
    if _model is None or not techniques:
        return None
    try:
        descriptions = [tech['description'] for tech in techniques]
        batch_size = 32
        all_embeddings = []
        
        for i in range(0, len(descriptions), batch_size):
            batch = descriptions[i:i+batch_size]
            batch_embeddings = _model.encode(batch, convert_to_tensor=True)
            all_embeddings.append(batch_embeddings)
        
        embeddings = torch.cat(all_embeddings, dim=0)
        return embeddings
    except Exception as e:
        st.error(f"Error computing embeddings: {e}")
        return None

@st.cache_data
def load_library_data_with_embeddings(_model):
    """Load library data and compute embeddings"""
    try:
        try:
            library_df = pd.read_csv("library.csv")
        except:
            library_df = pd.DataFrame(columns=['Use Case Name', 'Description', 'Log Source', 
                                               'Mapped MITRE Tactic(s)', 'Mapped MITRE Technique(s)', 
                                               'Reference Resource(s)', 'Search'])
        
        if library_df.empty:
            return None, None
        
        for col in library_df.columns:
            if library_df[col].dtype == 'object':
                library_df[col] = library_df[col].fillna("N/A")
        
        descriptions = []
        for desc in library_df['Description'].tolist():
            if pd.isna(desc) or isinstance(desc, float):
                descriptions.append("No description available")
            else:
                descriptions.append(str(desc))
        
        batch_size = 32
        all_embeddings = []
        
        for i in range(0, len(descriptions), batch_size):
            batch = descriptions[i:i+batch_size]
            batch_embeddings = _model.encode(batch, convert_to_tensor=True)
            all_embeddings.append(batch_embeddings)
        
        if all_embeddings:
            embeddings = torch.cat(all_embeddings, dim=0)
            return library_df, embeddings
        
        return library_df, None
        
    except Exception as e:
        st.warning(f"Could not load library: {e}")
        return None, None

def batch_check_library_matches(descriptions: List[str], 
                              library_df: pd.DataFrame,
                              library_embeddings: torch.Tensor,
                              _model: SentenceTransformer,
                              batch_size: int = 32,
                              similarity_threshold: float = 0.8) -> List[Tuple]:
    """Check for library matches"""
    if library_df is None or library_df.empty or library_embeddings is None:
        return [(None, 0.0, "No library data available") for _ in descriptions]
    
    results = []
    exact_matches = {}
    
    for i, desc in enumerate(descriptions):
        if pd.isna(desc) or desc is None or isinstance(desc, float):
            exact_matches[i] = (None, 0.0, "Invalid description")
            continue
            
        try:
            lower_desc = str(desc).lower()
            matches = library_df[library_df['Description'].str.lower() == lower_desc]
            if not matches.empty:
                exact_matches[i] = (matches.iloc[0], 1.0, "Exact match found in library")
        except Exception as e:
            exact_matches[i] = (None, 0.0, f"Error: {str(e)}")
    
    remaining_indices = [i for i in range(len(descriptions)) if i not in exact_matches]
    valid_indices = []
    valid_descriptions = []
    
    for idx in remaining_indices:
        desc = descriptions[idx]
        if pd.isna(desc) or desc is None or isinstance(desc, float):
            results.append((idx, (None, 0.0, "Invalid description")))
        else:
            valid_indices.append(idx)
            valid_descriptions.append(str(desc))
    
    if not valid_descriptions:
        return [exact_matches.get(i, (None, 0.0, "No match found")) for i in range(len(descriptions))]
    
    for i in range(0, len(valid_descriptions), batch_size):
        batch = valid_descriptions[i:i+batch_size]
        try:
            batch_embeddings = _model.encode(batch, convert_to_tensor=True)
            
            for j, query_embedding in enumerate(batch_embeddings):
                best_score, best_idx = cosine_similarity_search(query_embedding, library_embeddings)
                orig_idx = valid_indices[i + j]
                
                if best_score >= similarity_threshold:
                    results.append((orig_idx, (library_df.iloc[best_idx], best_score, 
                                f"Similar match found (score: {best_score:.2f})")))
                else:
                    results.append((orig_idx, (None, 0.0, "No match found")))
        except Exception as e:
            for j in range(len(batch)):
                if i+j < len(valid_indices):
                    orig_idx = valid_indices[i + j]
                    results.append((orig_idx, (None, 0.0, f"Error: {str(e)}")))
    
    all_results = []
    for i in range(len(descriptions)):
        if i in exact_matches:
            all_results.append(exact_matches[i])
        else:
            result_found = False
            for idx, result in results:
                if idx == i:
                    all_results.append(result)
                    result_found = True
                    break
            if not result_found:
                all_results.append((None, 0.0, "No match found"))
    
    return all_results

def map_with_claude_api(description: str, 
                        mitre_techniques: List[Dict],
                        candidate_indices: List[int] = None,
                        api_key: str = None,
                        model_name: str = "claude-haiku-4-5-20251001") -> Optional[Tuple]:
    """Use Claude API for mapping"""
    try:
        import anthropic
        
        if not api_key:
            return None
        
        cache_key = hashlib.md5(f"{description}_{model_name}".encode()).hexdigest()
        if cache_key in st.session_state.claude_cache:
            return st.session_state.claude_cache[cache_key]
        
        client = anthropic.Anthropic(api_key=api_key)
        
        candidates = []
        if candidate_indices:
            candidates = [mitre_techniques[idx] for idx in candidate_indices[:5]]
        else:
            candidates = mitre_techniques[:5]
        
        techniques_context = "\n".join([
            f"{i+1}. {tech['id']}: {tech['name']}\n   Tactics: {', '.join(tech.get('tactics_list', []))}\n   {tech['description'][:120]}..."
            for i, tech in enumerate(candidates)
        ])
        
        prompt = f"""Map this security use case to the most appropriate MITRE ATT&CK technique.

Use Case:
{description}

Candidate Techniques:
{techniques_context}

Respond in this EXACT format (no explanation):
TECHNIQUE_ID: [ID]
TECHNIQUE_NAME: [Name]
PRIMARY_TACTIC: [Tactic]
CONFIDENCE: [0.0-1.0]"""

        message = client.messages.create(
            model=model_name,
            max_tokens=200,
            temperature=0,
            messages=[{"role": "user", "content": prompt}]
        )
        
        response_text = message.content[0].text.strip()
        
        parsed = {}
        for line in response_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                parsed[key.strip()] = value.strip()
        
        technique_id = parsed.get('TECHNIQUE_ID', '').strip()
        technique_name = parsed.get('TECHNIQUE_NAME', '').strip()
        primary_tactic = parsed.get('PRIMARY_TACTIC', '').strip()
        
        try:
            confidence = float(parsed.get('CONFIDENCE', '0.85'))
        except:
            confidence = 0.85
        
        technique = next((t for t in mitre_techniques if t['id'] == technique_id), None)
        if technique:
            result = (
                primary_tactic,
                technique_name,
                technique.get('url', ''),
                technique.get('tactics_list', []),
                confidence
            )
            st.session_state.claude_cache[cache_key] = result
            return result
        
        return None
        
    except Exception as e:
        print(f"Claude API error: {e}")
        return None

def batch_map_to_mitre(descriptions: List[str], 
                      _model: SentenceTransformer, 
                      mitre_techniques: List[Dict], 
                      mitre_embeddings: torch.Tensor, 
                      batch_size: int = 32,
                      use_claude_api: bool = False,
                      api_key: str = None,
                      model_name: str = "claude-haiku-4-5-20251001") -> List[Tuple]:
    """Map descriptions to MITRE techniques"""
    if _model is None or mitre_embeddings is None:
        return [("N/A", "N/A", "N/A", [], 0.0) for _ in descriptions]
    
    results = []
    claude_threshold = 0.70
    
    mitre_embeddings_norm = mitre_embeddings / mitre_embeddings.norm(dim=1, keepdim=True)
    
    for i in range(0, len(descriptions), batch_size):
        batch = descriptions[i:i+batch_size]
        
        try:
            query_embeddings = _model.encode(batch, convert_to_tensor=True)
            query_embeddings_norm = query_embeddings / query_embeddings.norm(dim=1, keepdim=True)
            
            similarities = torch.mm(query_embeddings_norm, mitre_embeddings_norm.T)
            
            best_scores, best_indices = similarities.max(dim=1)
            top5_scores, top5_indices = torch.topk(similarities, k=5, dim=1)
            
            for j in range(len(batch)):
                score = best_scores[j].item()
                idx = best_indices[j].item()
                best_tech = mitre_techniques[idx]
                technique_name = best_tech['name']
                
                if use_claude_api and api_key and score < claude_threshold:
                    try:
                        candidate_list = top5_indices[j].tolist()
                        claude_result = map_with_claude_api(
                            batch[j], 
                            mitre_techniques,
                            candidate_indices=candidate_list,
                            api_key=api_key,
                            model_name=model_name
                        )
                        
                        if claude_result:
                            results.append(claude_result)
                            continue
                    except Exception as e:
                        print(f"Claude API error: {e}")
                
                results.append((
                    best_tech['tactic'], 
                    technique_name,
                    best_tech['url'], 
                    best_tech['tactics_list'], 
                    score
                ))
                
        except Exception as e:
            print(f"Mapping error: {e}")
            for _ in range(len(batch)):
                results.append(("Error", "Error", "Error", [], 0.0))
    
    return results

def process_mappings(df, _model, mitre_techniques, mitre_embeddings, library_df, library_embeddings,
                    use_claude_api=False, api_key=None, model_name="claude-haiku-4-5-20251001"):
    """Main mapping processing function"""
    similarity_threshold = 0.8
    
    descriptions = []
    for desc in df['Description'].tolist():
        if pd.isna(desc) or desc is None or isinstance(desc, float):
            descriptions.append("No description available")
        else:
            descriptions.append(str(desc))
    
    library_match_results = batch_check_library_matches(
        descriptions, library_df, library_embeddings, _model, similarity_threshold=similarity_threshold
    )
    
    model_map_indices = []
    model_map_descriptions = []
    
    tactics = []
    techniques = []
    references = []
    all_tactics_lists = []
    confidence_scores = []
    match_sources = []
    match_scores = []
    techniques_count = {}
    
    for _ in range(len(df)):
        tactics.append("N/A")
        techniques.append("N/A")
        references.append("N/A")
        all_tactics_lists.append([])
        confidence_scores.append(0)
        match_sources.append("N/A")
        match_scores.append(0)
    
    for i, library_match in enumerate(library_match_results):
        matched_row, match_score, match_source = library_match
        
        if matched_row is not None:
            tactic = matched_row.get('Mapped MITRE Tactic(s)', 'N/A')
            technique = matched_row.get('Mapped MITRE Technique(s)', 'N/A')
            reference = matched_row.get('Reference Resource(s)', 'N/A')
            
            tactics_list = tactic.split(', ') if tactic != 'N/A' else []
            confidence = match_score
            
            tactics[i] = tactic
            techniques[i] = technique
            references[i] = reference
            all_tactics_lists[i] = tactics_list
            confidence_scores[i] = round(confidence * 100, 2)
            match_sources[i] = match_source
            match_scores[i] = round(match_score * 100, 2)
            
            if '-' in technique:
                tech_id = technique.split('-')[0].strip()
                techniques_count[tech_id] = techniques_count.get(tech_id, 0) + 1
        else:
            if not (descriptions[i] == "No description available" or pd.isna(descriptions[i])):
                model_map_indices.append(i)
                model_map_descriptions.append(descriptions[i])
            else:
                match_sources[i] = "Invalid description"
    
    if model_map_descriptions:
        model_results = batch_map_to_mitre(
            model_map_descriptions, _model, mitre_techniques, mitre_embeddings,
            use_claude_api=use_claude_api,
            api_key=api_key,
            model_name=model_name
        )
        
        for (i, idx) in enumerate(model_map_indices):
            if i < len(model_results):
                tactic, technique_name, reference, tactics_list, confidence = model_results[i]
                
                found_tech = next((t for t in mitre_techniques if t['name'] == technique_name), None)
                if found_tech:
                    tech_id = found_tech['id']
                    
                    if use_claude_api and api_key and confidence > 0.80:
                        source = "Claude API mapping"
                    else:
                        source = "Model mapping"
                    
                    tactics[idx] = tactic
                    techniques[idx] = technique_name
                    references[idx] = reference
                    all_tactics_lists[idx] = tactics_list
                    confidence_scores[idx] = round(confidence * 100, 2)
                    match_sources[idx] = source
                    match_scores[idx] = 0
                    
                    techniques_count[tech_id] = techniques_count.get(tech_id, 0) + 1
 
    df['Mapped MITRE Tactic(s)'] = tactics
    df['Mapped MITRE Technique(s)'] = techniques
    df['Reference Resource(s)'] = references
    df['Confidence Score (%)'] = confidence_scores
    df['Match Source'] = match_sources
    df['Library Match Score (%)'] = match_scores
    
    return df, techniques_count

def create_navigator_layer(techniques_count):
    """Create MITRE Navigator layer JSON"""
    try:
        techniques_data = []
        for tech_id, count in techniques_count.items():
            techniques_data.append({
                "techniqueID": tech_id,
                "score": count,
                "color": "",
                "comment": f"Count: {count}",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })
        
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        
        layer = {
            "name": f"Security Use Cases Mapping - {current_date}",
            "versions": {
                "attack": "17",
                "navigator": "4.8.1",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": f"Mapping generated on {current_date}",
            "filters": {
                "platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers", "Office 365", "SaaS", "IaaS", "Google Workspace", "Azure AD"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": techniques_data,
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
                "minValue": 0,
                "maxValue": max(techniques_count.values()) if techniques_count else 1
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        return json.dumps(layer, indent=2), str(uuid.uuid4())
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}", ""

def load_lottie_url(url: str):
    """Load Lottie animation"""
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# Sidebar
with st.sidebar:
    st.image("https://attack.mitre.org/theme/images/mitre_attack_logo.png", width=200)
    
    selected = option_menu(
        "Navigation",
        ["Home", "Results", "Analytics", "Gap Analysis", "Suggestions", "Export"],
        icons=['house', 'table', 'graph-up', 'bullseye', 'search', 'box-arrow-down'],
        menu_icon="list",
        default_index=0,
    )
    
    st.session_state.page = selected.lower()
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This tool maps security use cases to MITRE ATT&CK framework:
    
    - Library matching (free)
    - NLP embeddings (free)
    - Claude API (optional, better accuracy)
    - Suggestions based on log sources
    - MITRE Navigator export
    """)
    
    st.markdown("---")
    st.markdown("© 2025 | v2.0.0")

# Load model and data
model = load_model()
mitre_techniques, tactic_mapping, tactics_list = load_mitre_data()
mitre_embeddings = get_mitre_embeddings(model, mitre_techniques)
st.session_state.mitre_embeddings = mitre_embeddings

library_df, library_embeddings = load_library_data_with_embeddings(model)
if library_df is not None:
    st.session_state.library_data = library_df
    st.session_state.library_embeddings = library_embeddings

st.session_state.model = model
st.session_state.mitre_techniques = mitre_techniques

# HOME PAGE
if st.session_state.page == "home":
    st.markdown("# 🛡️ MITRE ATT&CK Mapping Tool")
    st.markdown("### Map your security use cases to the MITRE ATT&CK framework")
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.markdown("### Upload Security Use Cases")
        
        lottie_upload = load_lottie_url("https://assets8.lottiefiles.com/packages/lf20_F0tVCP.json")
        if lottie_upload:
            st_lottie(lottie_upload, height=200, key="upload_animation")
        
        st.markdown("Upload a CSV file with columns: 'Use Case Name', 'Description', and 'Log Source'.")
        
        st.markdown("---")
        st.markdown("### ⚙️ Mapping Method")
        
        mapping_method = st.radio(
            "Select Mapping Method",
            options=["Free (Embeddings Only)", "Claude Haiku API", "Claude Sonnet API"],
            help="Free: 60-70% accuracy. Haiku: 80-85% accuracy. Sonnet: 90-95% accuracy."
        )
        
        use_claude_api = False
        api_key = None
        model_name = "claude-haiku-4-5-20251001"
        
        if mapping_method != "Free (Embeddings Only)":
            use_claude_api = True
            
            if mapping_method == "Claude Sonnet API":
                model_name = "claude-sonnet-4-5-20250514"
            
            if BACKEND_API_KEY:
                api_key = BACKEND_API_KEY
                st.success("✅ Using backend configured API key")
            else:
                api_key = st.text_input(
                    "Anthropic API Key",
                    type="password",
                    help="Get your API key at https://console.anthropic.com/"
                )
                
                if api_key:
                    st.success("✅ API key provided")
                else:
                    st.warning("⚠️ Please enter your API key")
        
        st.markdown("---")
        
        uploaded_file = st.file_uploader("Choose a CSV file", type="csv", key="file_upload")
        
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                st.session_state._uploaded_file = uploaded_file
                
                required_cols = ['Use Case Name', 'Description', 'Log Source']
                if not all(col in df.columns for col in required_cols):
                    st.error(f"CSV must contain: {', '.join(required_cols)}")
                else:
                    st.session_state.file_uploaded = True
                    st.success(f"✅ {len(df)} use cases loaded!")
                    
                    for col in df.columns:
                        if df[col].dtype == 'object' or col in required_cols:
                            df[col] = df[col].fillna("N/A")
                    
                    st.markdown("### Preview")
                    st.dataframe(df.head(5), use_container_width=True)
                    
                    if st.session_state.library_data is not None:
                        st.info(f"📚 Library: {len(st.session_state.library_data)} pre-mapped use cases")
                    
                    st.info(f"🎯 MITRE: {len(mitre_techniques)} active parent techniques")
                    
                    can_map = True
                    if use_claude_api and not api_key:
                        can_map = False
                        st.error("❌ API key required for Claude API mode")
                    
                    if can_map and st.button("Start Mapping", key="start_mapping"):
                        with st.spinner("Mapping in progress..."):
                            progress_bar = st.progress(0)
                            start_time = time.time()
                            
                            try:
                                df, techniques_count = process_mappings(
                                    df, 
                                    model, 
                                    mitre_techniques, 
                                    st.session_state.mitre_embeddings,
                                    st.session_state.library_data,
                                    st.session_state.library_embeddings,
                                    use_claude_api=use_claude_api,
                                    api_key=api_key,
                                    model_name=model_name
                                )
                                
                                st.session_state.processed_data = df
                                st.session_state.techniques_count = techniques_count
                                st.session_state.mapping_complete = True
                                
                                elapsed_time = time.time() - start_time
                                progress_bar.progress(100)
                                
                                st.success(f"✅ Mapping complete in {elapsed_time:.2f} seconds!")
                                st.info("Navigate to **Results** to view mapped data")
                                
                            except Exception as e:
                                st.error(f"Error: {str(e)}")
                                import traceback
                                st.error(traceback.format_exc())
                                
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
        
    with col2:
        st.markdown("### How It Works")
        
        with st.expander("📝 Requirements", expanded=True):
            st.markdown("""
            **Required CSV Columns:**
            - Use Case Name
            - Description
            - Log Source
            """)
        
        with st.expander("🔄 Process", expanded=True):
            st.markdown("""
            1. Upload CSV file
            2. Choose mapping method
            3. Library check (free, fast)
            4. New cases mapped via selected method
            5. View results in Results tab
            """)
        
        with st.expander("💡 Mapping Methods", expanded=False):
            st.markdown("""
            **Free (Embeddings):**
            - Accuracy: 60-70%
            - Cost: $0
            - Speed: Fast
            
            **Claude Haiku:**
            - Accuracy: 80-85%
            - Cost: ~$0.02-$0.05/100 cases
            - Speed: Moderate
            - Recommended
            
            **Claude Sonnet:**
            - Accuracy: 90-95%
            - Cost: ~$0.20-$0.30/100 cases
            - Speed: Slower
            - For critical systems
            """)

# RESULTS PAGE
elif st.session_state.page == "results":
    st.markdown("# 📊 Mapping Results")
    
    if st.session_state.mapping_complete and st.session_state.processed_data is not None:
        df = st.session_state.processed_data
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if 'Mapped MITRE Tactic(s)' in df.columns:
                tactics_series = df['Mapped MITRE Tactic(s)'].fillna("N/A")
                all_tactics = set()
                for tactic_str in tactics_series:
                    if isinstance(tactic_str, str):
                        for tactic in tactic_str.split(', '):
                            if tactic and tactic != 'N/A':
                                all_tactics.add(tactic)
                selected_tactics = st.multiselect("Filter by Tactics", options=sorted(list(all_tactics)), default=[])
        
        with col2:
            search_term = st.text_input("Search Descriptions", "")
        
        with col3:
            if 'Match Source' in df.columns:
                match_sources = df['Match Source'].fillna("Unknown").unique()
                selected_sources = st.multiselect("Filter by Source", options=match_sources, default=[])
        
        filtered_df = df.copy()
        
        if selected_tactics:
            mask = filtered_df['Mapped MITRE Tactic(s)'].fillna('').apply(
                lambda x: isinstance(x, str) and any(tactic in x for tactic in selected_tactics)
            )
            filtered_df = filtered_df[mask]
        
        if search_term:
            mask = filtered_df['Description'].fillna('').astype(str).str.contains(search_term, case=False, na=False)
            filtered_df = filtered_df[mask]
        
        if selected_sources:
            mask = filtered_df['Match Source'].fillna('Unknown').astype(str).apply(
                lambda x: any(source in x for source in selected_sources)
            )
            filtered_df = filtered_df[mask]
        
        st.markdown(f"**Showing {len(filtered_df)} of {len(df)} use cases**")
        st.dataframe(filtered_df, use_container_width=True)
        
        st.download_button(
            "Download Results as CSV",
            filtered_df.to_csv(index=False).encode('utf-8'),
            "mitre_mapped_results.csv",
            "text/csv"
        )
    
    else:
        st.info("No results available. Please upload and map your data on the Home page.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()

# ANALYTICS PAGE
elif st.session_state.page == "analytics":
    render_analytics_page(mitre_techniques)

# GAP ANALYSIS PAGE
elif st.session_state.page == "gap analysis":
    render_gap_analysis_page(mitre_techniques)

# SUGGESTIONS PAGE
elif st.session_state.page == "suggestions":
    render_suggestions_page()

# EXPORT PAGE
elif st.session_state.page == "export":
    st.markdown("# 💾 Export Navigator Layer")
    
    if st.session_state.mapping_complete and st.session_state.processed_data is not None:
        st.markdown("### MITRE ATT&CK Navigator Export")
        
        navigator_layer, layer_id = create_navigator_layer(st.session_state.techniques_count)
        
        st.markdown("""
        Export your mapping results for MITRE ATT&CK Navigator visualization.
        """)
        
        st.download_button(
            label="Download Navigator Layer JSON",
            data=navigator_layer,
            file_name="navigator_layer.json",
            mime="application/json",
            key="download_nav"
        )
        
        st.markdown("### How to Use")
        st.markdown("""
        1. Download the JSON file above
        2. Visit [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
        3. Click "Open Existing Layer" → "Upload from Local"
        4. Select the downloaded file
        """)
        
        with st.expander("View Navigator Layer JSON"):
            st.code(navigator_layer, language="json")
    
    else:
        st.info("No export data available. Please map your data first.")
        if st.button("Go to Home"):
            st.session_state.page = "home"
            st.experimental_rerun()
