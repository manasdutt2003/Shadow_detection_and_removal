import json
import random
import os
from datetime import datetime

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'train_stats.json')

MODELS = ['UNet', 'ResNet50', 'GAN', 'AutoEncoder']

def update_training_stats():
    # Load existing data or create new structure
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
        except:
            data = {"epochs": []}
    else:
        # Create directory if needed
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        data = {"epochs": []}

    # Simulate a training epoch
    current_epoch = len(data["epochs"]) + 1
    
    # Simulate loss going down over time (with noise)
    base_loss = max(0.01, 1.0 - (current_epoch * 0.005))
    loss = base_loss + random.uniform(-0.05, 0.05)
    
    # Simulate accuracy going up
    base_acc = min(0.99, 0.5 + (current_epoch * 0.005))
    accuracy = base_acc + random.uniform(-0.02, 0.02)
    
    epoch_data = {
        "epoch": current_epoch,
        "timestamp": datetime.now().isoformat(),
        "model": random.choice(MODELS),
        "loss": round(loss, 4),
        "accuracy": round(accuracy, 4),
        "images_processed": random.randint(100, 500)
    }
    
    data["epochs"].append(epoch_data)
    
    # Keep file size manageable
    if len(data["epochs"]) > 100:
        data["epochs"] = data["epochs"][-100:]

    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Epoch {current_epoch} complete. Loss: {loss:.4f}, Accuracy: {accuracy:.4f}")

if __name__ == "__main__":
    update_training_stats()
