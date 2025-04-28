# Always Authenticated, Never Exposed: Continuous Authentication via Zero-Knowledge Proofs

## Overview
This repository contains the code, documentation, implementation details, and protocols for our paper: "Always Authenticated, Never Exposed: Continuous Authentication via Zero-Knowledge Proofs" The paper examines the integration and impact of (NI)ZKP in enhancing continuous authentication. To demonstrate this, we developed a simple continuous authentication system and integrated it with the protocol described in the paper to support (NI)ZKP.

Below we further detail our protocols. Specifically, we first detail the enrollment protocol, followed by the interactive and non-interactive authentication protocols. For information on how to install and run our PoC refer to our [PoC](poc.md) and a more detailed explaination of the system architecture is provided [here](architecture.md).

## Enrollment Protocol

First, the user must send their biometric images, a password, and additional metadata to the IdP, as shown in Figure 1 below. Next, the IdP selects random images from its database according to the scheme described in "Training Data" and extracts features from these images as well as the user’s submitted image. A randomly generated 128-bit class label is assigned to the extracted features for each person and used to train the multi-class SVM, as further detailed in "SVM"". 

After the training process, the enrolment user’s images are deleted from the IdP, as they are no longer required. Next, a random 128-bit salt value is generated. This salt is combined with the user’s password to derive three passwords (S1, S2, S3) using the **Password-Based Key Derivation Function 2 (PBKDF2)**. The PBKDF2 enables the deterministic and cryptographically secure derivation of multiple passwords from a single input. This allows the user to enter only one password while generating three distinct passwords for different application purposes.

The **BID** is then created using the output of the multi-class SVM, specifically the class label of the legitimate user, combined with S1, as detailed in "BID". A Pedersen commitment $ C = g^x h^r \mod p $ is subsequently constructed, where \( x = \text{BID} \) and \( r = S2 \). This commitment is supplemented with metadata and a signature over the commitment and the metadata to form the **IDT**. The metadata includes at minimum the Social Security number and the public parameters of the Pedersen commitment, which is further discussed in "Metadata".

Finally, Gunasinghe and Bertino generate an asymmetric key pair to encrypt the classifier, without providing a justification for preferring an asymmetric approach over a symmetric one. Since the key pair is solely used for encryption, we opted for a symmetric key and employed AES, as it offers greater efficiency and faster encryption. This key is then encrypted with S3 and sent to the user along with the encrypted classifier, the IDT, and the salt value.

In summary:
- **S1** is utilised for the BID  
- **S2** for the commitment  
- **S3** for encrypting the key pair  

---

### Training Data

With each new enrolment, the server automatically selects the training data from a predefined set of individuals. The optimal training set size has been determined according to the objectives and methodology outlined in the paper. Based on the evaluation results, the training dataset comprises images from **30 randomly selected individuals** out of the **62 available**, along with at least **ten images** that the enrolling user must upload. The number of images per training individual varies depending on availability but includes a minimum of **20 images per person**.

---

### Feature Extraction

For feature extraction, we utilised **Inception-ResNet v1** from the `facenet_pytorch` library, pre-trained on the **VGGFace2** database. If a compatible graphics card is available, it is used to accelerate the process. The classification function of the model is deactivated, as classification is performed by the SVM. 

Since the images are already aligned, they are resized to **160x160 pixels**, as recommended by the authors. The images are then normalised, and a batch dimension is added to format them correctly for the model.

> Note: Determining the optimal batch size is outside the scope of this work; a batch size of one is used.

The model outputs **512-dimensional embeddings** of the images, which are stored as **NumPy arrays**.

---

### BID

After selecting the training users, a **128-bit random number** is generated for each user, including the enrolment user. This number serves as a class label and is used, along with the extracted features, to train the **multi-class SVM**.

The class label is then concatenated with **S1** to form the **BID**, defined as: BID = Cl∥S1


This design ensures **revocability**, **uniqueness**, and **repeatability**. The password-derived secret (S1) enhances security by ensuring that even if the same user retrains, a different BID is created.

---

### SVM

For the SVM implementation, we used the `sklearn` package from the **scikit-learn** library, specifically the **SVC** module. When invoking the method, kernel type and hyperparameters can be specified.

The chosen configuration:

- Kernel: **RBF**
- Gamma: **0.03125**
- C: **8**

Results:

- **99.37% accuracy** on the test dataset
- **97.82% accuracy** on the validation dataset

---

### Metadata

Since there is no direct communication between the **SP** and the **IdP**, the SP queries its continuous authentication server to check for an **active session**. The metadata must uniquely identify the user. Gunasinghe and Bertino propose including:

- **Name**
- **Email**
- **Social Security number**

Despite its sensitivity, the Social Security number is adopted since it is only stored within the **IDT** and accessed only by **trusted SPs**.

The metadata also includes public parameters of the **Pedersen commitment**, required for computing commitments during the authentication protocol:

- **p** and **q**: large prime numbers
- **g** and **h**: generators of the cyclic group

A **timestamp** from the IdP is also included, defining the **validity period** of the IDT. Once expired, the enrolment process must be repeated.

![Figure 1: Enrollment Protocol](enrollment_protocol.PNG)

# Interactive Authentication Protocol

## Authentication Protocol Phases

The authentication protocol consists of two main phases.

Phase one is responsible for initial authentication, mutual identity verification, key exchange, and transmission of additional parameters. This phase corresponds to Steps 1–17 (see [Interactive Authentication Protocol](#interactive-authentication-protocol-diagram)) and is executed only once.
Phase two focuses exclusively on continuous authentication and covers all steps beyond Step 17. It is executed iteratively until authentication is terminated.

We first describe the steps of Phase one, followed by Phase two, and explain the necessity of specific steps.

---

## Phase One

The user initiates authentication by sending their identity token $\text{IDT}$ and a helper Pedersen commitment $d$ to the service provider (SP). The value $d$ is defined as:

$$
d = g^y h^s \mod p \in G_q
$$

where $y, s \in \mathbb{Z}_q$ are randomly selected secrets.

The SP verifies the validity of the signature, ensures the timestamp has not expired, and confirms that the user is not present on the revocation list.

Additionally, the SP generates a session timer, allowing each SP to define a maximum session duration according to security requirements. Subsequently, the SP generates parameters $e, w, a,$ and $b$ and transmits $e, a, b,$ and $t$ to the user. The session timer is displayed within the user interface, indicating the remaining validity period.

Upon receiving these values, the user captures an image and derives passwords $S_1', S_2', S_3'$ from the previously entered password. The password $S_3'$ decrypts the key store, allowing access to the symmetric key used to decrypt the classifier. After decoding the classifier, image features are extracted and passed to the SVM for class label prediction. The SVM remains decrypted throughout the session.

The issued class label is concatenated with $S_1'$ to form the binding identifier (BID). The user computes:

$$
u = y + ex
$$
$$
v = s + er
$$

where $x = \text{BID}'$ and $r = S_2'$. The user transmits $u$ and $v$ to the SP.

The SP verifies the following equation:

$$
g^u h^v = d C^e
$$

If the equation holds, authentication is successful; otherwise, it fails.

To confirm correctness:

Given

$$
C = g^x h^r
$$

it follows that

$$
C^e = (g^x h^r)^e = g^{xe} h^{re}
$$

Thus,

$$
dC^e = (g^y h^s)(g^{xe} h^{re}) = g^{y+xe} h^{s+re}
$$

Since $u = y + ex$ and $v = s + er$, it follows that:

$$
g^u h^v = g^{y+ex} h^{s+er}
$$

confirming the correctness of the verification equation.

Following successful verification, the user and SP independently derive a shared symmetric key. The key derivation depends solely on the user's $x$ and the SP's $w$, which are never exchanged. Consequently, only the legitimate user and SP can compute the key, mitigating the risk of impersonation attacks.

Moreover, since the session key depends on the SP's commitment $C$, a malicious SP cannot mount a man-in-the-middle attack by forwarding challenges and responses. Therefore, the user communicating with the SP is ensured to be authentic.

The final step of Phase one consists of a secure handshake based on the derived symmetric key.

---

## Phase Two

In Phase two, the user sends a new helper commitment $d$, but it is unnecessary to resend the identity token $\text{IDT}$. Reusing the same $d$ without regeneration introduces security vulnerabilities: the SP could recover the private key $x$ and random value $r$ by observing multiple responses.

Specifically, for two different challenges $e_1$ and $e_2$, the SP receives:

$$
u_1 = y + e_1 x
$$
$$
v_1 = s + e_1 r
$$
$$
u_2 = y + e_2 x
$$
$$
v_2 = s + e_2 r
$$

Subtracting the first pair of equations:

$$
u_2 - u_1 = (e_2 - e_1)x
\quad \Rightarrow \quad
x = \frac{u_2 - u_1}{e_2 - e_1}
$$

Similarly:

$$
v_2 - v_1 = (e_2 - e_1)r
\quad \Rightarrow \quad
r = \frac{v_2 - v_1}{e_2 - e_1}
$$

Thus, the SP could compute the user's secrets if a new $d$ is not generated for each iteration.

During continuous authentication, the SP issues a new challenge and verifies the session timer without regenerating the session key. Authentication steps mirror those from Phase one, except that no new password derivations or classifier decryption is required.

The user transmits $u$ and $v$ values, which the SP verifies before returning the authentication result. These steps are repeated until the session is terminated either:

- By the user via the application,
- Upon expiration of the session timer, or
- Following an authentication or zero-knowledge proof (ZKP) failure.

### Interactive Authentication Protocol Diagram
![Interactive Authentication Protocol](interactive_authentication_protocol.PNG)
---

## Extension to Non-Interactive Authentication Protocol

The enrolment protocol remains unchanged, as no modifications are required to ensure compatibility with the non-interactive variant of our authentication protocol. Therefore, we focus solely on the authentication protocol and its modifications.

Specifically, by a non-interactive protocol, we refer to a setting where the challenge is generated directly by the prover. However, a minimal degree of interaction remains necessary to maintain continuous authentication, as the proof's validity must still be verified.

Phase one of the interactive protocol remains unchanged. In the initial draft, the prover generated the challenge $e$, while the service provider (SP) generated a nonce and a timestamp. These could later be incorporated into challenge generation to prevent replay attacks.

After further consideration, we opted to initiate the challenge during this phase through the verifier rather than implementing a fully non-interactive approach for two reasons:

1. Since an exchange already occurs at this stage, the argument for reduced network overhead is not applicable.
2. The nonce and timestamp introduce additional randomness but also extra computational overhead, which can be avoided by letting the verifier generate the challenge directly.

Thus, removing the separate generation of nonce and timestamp reduces both complexity and computational effort.

## Phase Two: Transition to Non-Interactive Protocol

Starting from Step 18, Phase two undergoes significant modifications, transitioning towards a non-interactive form.

Instead of the prover transmitting the commitment $d$ to the verifier, the verifier independently constructs the challenge following a fixed scheme based on the strong Fiat-Shamir transformation. Specifically, the challenge is derived as:

$$
e = H(C \parallel d \parallel e'_i)
$$

where:
- $H$ denotes a cryptographically secure hash function (SHA-256),
- $C$ is the commitment,
- $d$ is the helper commitment,
- $e'_i$ is the incremented challenge for the $i$-th iteration.

The prover proceeds as before.

Thereafter, the SP:

- Validates the session's status using the session timer,
- Derives the challenge following the same logic,
- Verifies that:

$$
e_{\text{SP}} = e_{\text{prover}}
$$

- Finally, verifies the zero-knowledge proof (ZKP).

If both conditions are satisfied, the SP returns the authentication result to the user.

These steps are repeated throughout the continuous authentication session until it is terminated.

---

## Challenge Construction

When applying the strong Fiat-Shamir transformation to the ZKP protocol, the challenge is initially defined as:

$$
e = H(C \parallel d)
$$

where $H$ is the SHA-256 hash function.

Although our protocol already integrates replay attack countermeasures through key exchange and encryption, we further strengthen robustness by incorporating the incremented server-generated challenge $e'_i$ into the hash computation. Thus, the challenge is computed as:

$$
e = H(C \parallel d \parallel e'_i)
$$

This mechanism ensures that intercepted challenges cannot be reused by an attacker, as $e'_i$ changes at each protocol iteration, even if $d$ remains the same.

Consequently, each new authentication step produces a unique challenge, maintaining the protocol's resistance to replay attacks.

### Non-Interactive Authentication Protocol Diagram
![Non-Interactive Authentication Protocol](non-interactive_authentication_protocol.PNG)

## Authors

Dennis Hamm, Erwin Kurpis, Thomas Schreck

Contact for questions: d.hamm@tar.de

