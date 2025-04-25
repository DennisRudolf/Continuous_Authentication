import os
import torch
import numpy as np
from PIL import Image
from facenet_pytorch import InceptionResnetV1
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
import pickle
import random

class FaceRecognitionModel:
    def init_model(self, folder_path_target_user, names, device=None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') if device is None else device
        self.model = InceptionResnetV1(pretrained='vggface2').eval().to(self.device) # loads inceptionresnet

        self.folder_path = os.path.join(os.path.dirname(__file__), "Training_Data") # folder with training data
 
        self.images, self.user_ids = self.load_images_from_folders(names)
        self.target_user_images, self.target_user_label = self.load_target_user_images(folder_path_target_user) # gets the images for the target/enrolment user

        self.biometric_features = [self.get_face_embedding(img) for img in self.images]
        self.target_user_features = [self.get_face_embedding(img) for img in self.target_user_images]
        
        self.classifier = None
        self.label_encoder = None

    def get_target_user_label(self):
        return self.target_user_label
    
    def load_images_from_folders(self, folder_names):
            images = []
            labels = []

            folder_names_set = set(folder_names)
            folder_label_map = {}  

            for subdir, dirs, files in os.walk(self.folder_path):
                current_folder_name = os.path.basename(subdir)

                if current_folder_name in folder_names_set:
                    if current_folder_name not in folder_label_map: # chooses the training users
                        random_128_bit = random.getrandbits(128) # generates the random label
                        folder_label_map[current_folder_name] = f"{random_128_bit:032x}" # maps it to a user

                    label = folder_label_map[current_folder_name]

                    for file in files:
                        if file.lower().endswith(".jpg"): 
                            path = os.path.join(subdir, file)
                            try:
                                img = Image.open(path).convert('RGB')
                                images.append(img)
                                labels.append(label)
                                #print(f"Bild: {file}, Ordner: {current_folder_name}, Label: {label}")
                            except Exception as e:
                                print(f"Error while loading the image {path}: {e}")
            return images, labels
    
    def load_target_user_images(self, target_user_folder):
        images = []

        random_128_bit = random.getrandbits(128)
        target_user_label = f"{random_128_bit:032x}" 

        for subdir, dirs, files in os.walk(target_user_folder):
            for file in files:
                if file.lower().endswith(".jpg"): 
                    path = os.path.join(subdir, file)
                    try:
                        img = Image.open(path).convert('RGB')
                        images.append(img)
                        #print(f"Bild: {file}, Ordner: {os.path.basename(subdir)}, Label: {target_user_label}")
                    except Exception as e:
                        print(f"Error while loading the image {path}: {e}")
        return images, target_user_label
    
    def get_face_embedding(self, img): # extracts the face embeddings from the images used later for training
        img = img.resize((160, 160))
        img = torch.tensor(np.array(img) / 255.).permute(2, 0, 1).float().unsqueeze(0)
        embedding = self.model(img)
        return embedding.detach().numpy().flatten()

    def train_classifier(self):
        all_features = self.biometric_features + self.target_user_features
        all_labels = self.user_ids + [self.target_user_label] * len(self.target_user_features)
        le = LabelEncoder()
        labels_encoded = le.fit_transform(all_labels)

        classifier = SVC(kernel='rbf', gamma=0.03125, C=8, probability=True) # hyperparameters and probabilty set as described in the thesis for optimal model
        classifier.fit(all_features, labels_encoded)

        self.classifier = classifier
        self.label_encoder = le

    def save_model(self, filename="face_classifier.pkl"): # saves the classifier that it can be send to the user later
        if self.classifier is None or self.label_encoder is None:
            raise ValueError("Training didn't work, please retry")

        current_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(current_dir, filename)
        
        with open(filepath, 'wb') as f:
            pickle.dump((self.classifier, self.label_encoder), f)
