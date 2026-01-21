import streamlit as st
import torch
from torchvision import transforms
from PIL import Image
import os
import sys

# Add project root to path to import models
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Try importing models, handle failures if files are missing/broken
try:
    from shadow_desdnet import ShadowDESDNet
    from shadow_removal import ShadowRemoval
except ImportError as e:
    st.error(f"Error importing models: {e}")
    st.stop()

st.set_page_config(page_title="Shadow Detection & Removal", page_icon="🌤️", layout="wide")

st.title("🌤️ Shadow Detection & Removal System")
st.markdown("""
This application detects and removes shadows from images using Deep Learning.
Upload an image to see the Shadow Mask and the Shadow-Free result.
""")

# Sidebar for configuration
st.sidebar.header("Configuration")
model_path = st.sidebar.text_input("Model Checkpoint Path", "checkpoints/best_model.pth")

@st.cache_resource
def load_models(checkpoint_path):
    if not os.path.exists(checkpoint_path):
        return None, None, f"Checkpoint not found at: {checkpoint_path}"
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    try:
        detector = ShadowDESDNet().to(device)
        remover = ShadowRemoval().to(device)
        
        checkpoint = torch.load(checkpoint_path, map_location=device)
        detector.load_state_dict(checkpoint['detector_state'])
        remover.load_state_dict(checkpoint['remover_state'])
        
        detector.eval()
        remover.eval()
        
        return detector, remover, None
    except Exception as e:
        return None, None, str(e)

def process_image(image, detector, remover):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Preprocess
    transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.5, 0.5, 0.5], std=[0.5, 0.5, 0.5])
    ])
    
    img_tensor = transform(image).unsqueeze(0).to(device)
    
    with torch.no_grad():
        # Inference
        shadow_mask = detector(img_tensor)
        shadow_free = remover(img_tensor, shadow_mask)
        
    # Post-process
    # Mask is 1-channel, Output is 3-channel
    mask_vis = shadow_mask.squeeze().cpu().numpy()
    
    shadow_free_vis = (shadow_free.squeeze().cpu().permute(1, 2, 0) * 0.5 + 0.5).clamp(0, 1).numpy()
    
    return mask_vis, shadow_free_vis

# Main app logic
uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "png", "jpeg"])

if uploaded_file is not None:
    image = Image.open(uploaded_file).convert('RGB')
    
    # Display original
    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Original Image")
        st.image(image, use_container_width=True)
    
    # Load models
    detector, remover, error = load_models(model_path)
    
    if error:
        st.warning(f"⚠️ Model weights missing or invalid.\n\n{error}")
        st.info("Please ensure 'checkpoints/best_model.pth' is present in the repository or upload it if supported.")
        
        # Optional: Allow uploading weights if missing? 
        # For now, just stopping.
    elif detector and remover:
        with st.spinner("Processing image..."):
            mask, result = process_image(image, detector, remover)
            
        with col2:
            st.subheader("Detected Shadow Mask")
            st.image(mask, use_container_width=True, cmap='gray')
            
        with col3:
            st.subheader("Shadow Removed")
            st.image(result, use_container_width=True)

st.divider()
st.markdown("Developed by Manas Dutt | [GitHub Repository](https://github.com/manasdutt2003/Shadow_detection_and_removal)")
