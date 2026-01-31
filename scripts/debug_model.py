
import sys
import os
from pathlib import Path

# Add services/backend to path so we can import 'app'
backend_path = Path(__file__).resolve().parents[1] / "services" / "backend"
sys.path.append(str(backend_path))

print(f"Python Path: {sys.path}")
print(f"CWD: {os.getcwd()}")

try:
    from app.config import settings
    from app.models_loader import network_ml_model
    
    print("--- Configuration ---")
    print(f"Network Model Path: {settings.network_model_path}")
    print(f"File Exists: {os.path.exists(settings.network_model_path)}")
    
    print("\n--- Loading Model ---")
    success = network_ml_model.load(
        settings.network_model_path,
        settings.network_features_path,
        settings.network_labels_path,
        settings.network_preprocess_path
    )
    
    print(f"\nLoad Result: {success}")
    
    if success:
        print(f"Features Loaded: {len(network_ml_model.feature_list)}")
        print(f"Label Map: {network_ml_model.label_map.keys()}")
    else:
        print("Detailed check of files:")
        print(f"Model: {os.path.exists(settings.network_model_path)}")
        print(f"Features: {os.path.exists(settings.network_features_path)}")
        print(f"Labels: {os.path.exists(settings.network_labels_path)}")
        print(f"Load Error: {network_ml_model.load_error}")

except Exception as e:
    print(f"\nCRITICAL ERROR: {e}")
    import traceback
    traceback.print_exc()
