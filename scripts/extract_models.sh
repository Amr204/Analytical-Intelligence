#!/bin/bash
# =====================================================
# Analytical-Intelligence v1 - Model Extraction Script
# =====================================================
# This script extracts models from zip files if they exist.
# It is idempotent - running multiple times is safe.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

SSH_MODEL_DIR="$PROJECT_ROOT/models/ssh"
NETWORK_MODEL_DIR="$PROJECT_ROOT/models/network"

echo "========================================"
echo "Analytical-Intelligence v1 - Model Extraction"
echo "========================================"

# Create model directories if they don't exist
mkdir -p "$SSH_MODEL_DIR"
mkdir -p "$NETWORK_MODEL_DIR"

# Check if SSH model already exists
if [ -f "$SSH_MODEL_DIR/ssh_lstm.joblib" ]; then
    echo "[✓] SSH LSTM model already exists at: $SSH_MODEL_DIR/ssh_lstm.joblib"
else
    # Try to copy from Host-Model directory
    if [ -f "$PROJECT_ROOT/models/Host-Model/ssh_lstm.joblib" ]; then
        echo "[→] Copying SSH LSTM model from Host-Model..."
        cp "$PROJECT_ROOT/models/Host-Model/ssh_lstm.joblib" "$SSH_MODEL_DIR/"
        echo "[✓] SSH LSTM model copied successfully!"
    # Try to extract from AI.zip
    elif [ -f "$PROJECT_ROOT/AI.zip" ]; then
        echo "[→] Extracting SSH model from AI.zip..."
        unzip -o "$PROJECT_ROOT/AI.zip" -d "$SSH_MODEL_DIR/"
        echo "[✓] SSH model extracted successfully!"
    else
        echo "[!] Warning: SSH model not found. Please place ssh_lstm.joblib in $SSH_MODEL_DIR"
    fi
fi

# Check if network model already exists
if [ -f "$NETWORK_MODEL_DIR/model.joblib" ]; then
    echo "[✓] Network ML model already exists at: $NETWORK_MODEL_DIR/model.joblib"
else
    # Try to copy from Network-Model directory
    if [ -f "$PROJECT_ROOT/models/Network-Model/model.joblib" ]; then
        echo "[→] Copying Network ML artifacts from Network-Model..."
        cp "$PROJECT_ROOT/models/Network-Model/model.joblib" "$NETWORK_MODEL_DIR/"
        cp "$PROJECT_ROOT/models/Network-Model/feature_list.json" "$NETWORK_MODEL_DIR/"
        cp "$PROJECT_ROOT/models/Network-Model/label_map.json" "$NETWORK_MODEL_DIR/"
        cp "$PROJECT_ROOT/models/Network-Model/preprocess_config.json" "$NETWORK_MODEL_DIR/"
        echo "[✓] Network ML artifacts copied successfully!"
    # Try to extract from ids_artifacts.zip
    elif [ -f "$PROJECT_ROOT/ids_artifacts.zip" ]; then
        echo "[→] Extracting Network model from ids_artifacts.zip..."
        unzip -o "$PROJECT_ROOT/ids_artifacts.zip" -d "$NETWORK_MODEL_DIR/"
        echo "[✓] Network model extracted successfully!"
    else
        echo "[!] Warning: Network model not found. Please place artifacts in $NETWORK_MODEL_DIR"
    fi
fi

echo ""
echo "========================================"
echo "Model Status Summary"
echo "========================================"

# Verify SSH model
if [ -f "$SSH_MODEL_DIR/ssh_lstm.joblib" ]; then
    echo "[✓] SSH LSTM:    $SSH_MODEL_DIR/ssh_lstm.joblib"
else
    echo "[✗] SSH LSTM:    MISSING"
fi

# Verify Network model files
if [ -f "$NETWORK_MODEL_DIR/model.joblib" ]; then
    echo "[✓] Network ML:  $NETWORK_MODEL_DIR/model.joblib"
else
    echo "[✗] Network ML:  MISSING"
fi

if [ -f "$NETWORK_MODEL_DIR/feature_list.json" ]; then
    echo "[✓] Features:    $NETWORK_MODEL_DIR/feature_list.json"
else
    echo "[✗] Features:    MISSING"
fi

if [ -f "$NETWORK_MODEL_DIR/label_map.json" ]; then
    echo "[✓] Labels:      $NETWORK_MODEL_DIR/label_map.json"
else
    echo "[✗] Labels:      MISSING"
fi

if [ -f "$NETWORK_MODEL_DIR/preprocess_config.json" ]; then
    echo "[✓] Preprocess:  $NETWORK_MODEL_DIR/preprocess_config.json"
else
    echo "[✗] Preprocess:  MISSING"
fi

echo ""
echo "Done!"
