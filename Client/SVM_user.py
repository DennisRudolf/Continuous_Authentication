import os
import torch
import numpy as np
from PIL import Image
from facenet_pytorch import InceptionResnetV1
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
import pickle
import time

def load_model(model_filename="face_classifier.pkl"): # loads the pretrained model
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, model_filename)
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file {model_filename} not found.")
    
    with open(model_path, 'rb') as f:
        classifier, label_encoder = pickle.load(f)
    
    return classifier, label_encoder

def get_face_embedding(img, model): # extracts the face embeddings
    img = img.resize((160, 160))
    img = torch.tensor(np.array(img) / 255.).permute(2, 0, 1).float().unsqueeze(0)
    embedding = model(img)
    return embedding.detach().numpy().flatten()

def predict_label(image_path, model_filename="face_classifier_decrypted.pkl"): # predicts the label for the user
    threshold = 0.15
    model = InceptionResnetV1(pretrained='vggface2').eval()
    classifier, label_encoder = load_model(model_filename)
    img = Image.open(image_path).convert('RGB')
    embedding = get_face_embedding(img, model)

    probabilities = classifier.predict_proba([embedding])
    max_prob = np.max(probabilities)
    predicted_label_encoded = np.argmax(probabilities)

    if max_prob < threshold: # chekcs if the probability is bigger than the threshold
        return None

    predicted_label = label_encoder.inverse_transform([predicted_label_encoded])
    
    return predicted_label[0]