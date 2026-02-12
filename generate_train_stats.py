import json
import random
from datetime import datetime
import os

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'train_stats.json')

def generate_stats():
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Simulate gradual improvement
    current_loss = round(random.uniform(0.01, 0.05), 4)
    current_psnr = round(random.uniform(25.0, 35.0), 2)
    current_ssim = round(random.uniform(0.85, 0.99), 3)

    stats = {
        "date": today,
        "epochs_completed": random.randint(100, 500),
        "loss": current_loss,
        "psnr": current_psnr,
        "ssim": current_ssim,
        "gpu_utilization_avg": f"{random.randint(70, 95)}%"
    }

    try:
        with open(DATA_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
        print(f"Successfully generated training stats for {today}: {stats}")
    except Exception as e:
        print(f"Error generating stats: {e}")
        exit(1)

if __name__ == "__main__":
    generate_stats()
