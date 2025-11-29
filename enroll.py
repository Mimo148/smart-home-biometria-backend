from deepface import DeepFace
import numpy as np
import os

# 1) Zistíme, kde leží tento súbor (enroll.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2) Cesta k owner.jpg v tom istom priečinku
IMAGE_PATH = os.path.join(BASE_DIR, "owner2.jpg")

os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

# 3) Spravíme embedding tváre
result = DeepFace.represent(img_path=IMAGE_PATH, model_name="Facenet")[0]

owner_template = np.array(result["embedding"])

# 4) Uložíme šablónu
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "owner2.npy")
np.save(TEMPLATE_PATH, owner_template)

print("✅ Enrolment hotový – šablóna uložená do", TEMPLATE_PATH)