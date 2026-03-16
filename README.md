# 🛡️ Phishing URL Detector

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://phishing-url-detector-webapp.streamlit.app/)
[![GitHub license](https://img.shields.io/github/license/AsadAbbasdev/Phishing-URL-Detection-using-ML)](https://github.com/AsadAbbasdev/Phishing-URL-Detection-using-ML/blob/main/LICENSE)
[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-310/)
[![Machine Learning](https://img.shields.io/badge/ML-Gradient%20Boosting-orange)](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.GradientBoostingClassifier.html)

<div align="center">
  <img src="https://img.icons8.com/color/96/000000/security-checked.png" alt="Phishing Detection Logo"/>
  <h3>🔍 Detect Phishing Websites with 97.4% Accuracy in Real-Time</h3>
  <p><i>Your first line of defense against online scams and fraudulent URLs</i></p>
</div>

---

## ✨ Live Demo

**🚀 Experience the app live:** [phishing-url-detector-webapp.streamlit.app](https://phishing-url-detector-webapp.streamlit.app/)

No installation required. Just paste a URL and get instant results!

---

## 📸 App Sneak Peek

| Safe URL Detection | Phishing URL Alert | Feature Analysis |
|:---:|:---:|:---:|
| ![Safe URL](https://via.placeholder.com/300x200/28a745/ffffff?text=✅+Safe+URL) | ![Phishing Alert](https://via.placeholder.com/300x200/dc3545/ffffff?text=⚠️+Phishing+Detected) | ![Analysis](https://via.placeholder.com/300x200/007bff/ffffff?text=📊+30+Features) |

*(Note: Add actual screenshots of your app here for best results)*

---

## 🎯 Key Features

- **⚡ Real-Time Detection**: Analyze any URL in seconds
- **🎯 97.4% Accuracy**: Powered by Gradient Boosting Classifier
- **🔬 30-Point Feature Check**: In-depth URL structure analysis
- **📈 Confidence Scores**: See how confident the model is
- **📊 Visual Insights**: Feature importance graphs
- **🌐 Live & Free**: Accessible anywhere, anytime

---

## 🛠️ Technology Stack

<details>
<summary>Click to expand</summary>

### Frontend
- **Streamlit** - Interactive web framework
- **HTML/CSS** - Custom styling

### Backend & ML
- **Python 3.10** - Core programming language
- **Scikit-learn** - Gradient Boosting implementation
- **XGBoost** & **CatBoost** - Ensemble learning
- **Pandas** & **NumPy** - Data processing
- **Joblib** - Model serialization

### Web Scraping & Analysis
- **BeautifulSoup4** - HTML parsing
- **Requests** - HTTP requests
- **python-whois** - Domain information
- **lxml** - XML/HTML processing

### Visualization
- **Matplotlib** & **Seaborn** - Data visualization

</details>

---

## 🏗️ Project Architecture
phishing-detection-app/
├── app.py # Main Streamlit application
├── requirements.txt # Project dependencies
├── README.md # You are here!
├── runtime.txt # Python version specification
├── packages.txt # System dependencies
├── models/ # Trained ML models
│ └── model.pkl # 97.4% accurate Gradient Boosting model
├── utils/ # Utility functions
│ └── preprocessing.py # 30-point feature extraction
├── data/ # Dataset
│ └── phishing.csv # Training data (11,000+ URLs)
└── notebooks/ # Jupyter notebooks
└── Phishing_URL_Detection.ipynb

---

## 🚀 How to Use

### 1️⃣ **Visit the Live App**
👉 [phishing-url-detector-webapp.streamlit.app](https://phishing-url-detector-webapp.streamlit.app/)

### 2️⃣ **Enter a URL**
Paste any URL in the input box (e.g., `https://google.com` or `http://suspicious-paypal-verify.tk`)

### 3️⃣ **Click "Check URL"**
The AI analyzes 30+ features in real-time

### 4️⃣ **View Results**
- ✅ **Safe URL**: Green box with high confidence
- ⚠️ **Phishing URL**: Red alert with warning
- 📊 **Detailed Analysis**: See which features triggered the alert

---

## 🧪 Test It Yourself

### ✅ Safe URLs (Should show green)
https://www.google.com
https://www.github.com
https://www.python.org
https://www.microsoft.com


### ⚠️ Phishing URLs (Should show red)
http://paypal-verification-alerts.tk
http://secure-bankofamerica-login.cc
http://amazon-order-confirm.xyz
http://netflix-account-update.ml
http://facebook-security-alerts.ga

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 97.4% |
| **Precision** | 98.6% |
| **Recall** | 99.4% |
| **F1-Score** | 97.7% |

---

## 🔍 30-Point Feature Analysis

The model examines these URL characteristics:

| Category | Features Analyzed |
|----------|-------------------|
| **URL Structure** | IP address, URL length, @ symbol, double slash, prefix-suffix |
| **Domain Info** | Subdomains, HTTPS token, domain age, DNS record |
| **Security** | SSL state, port number, HTTPS presence |
| **Page Analysis** | Request URL, anchor URL, links in tags, SFH |
| **Behavioral** | Pop-ups, iframes, right-click disable, forwarding |
| **Popularity** | Website traffic, PageRank, Google index |
| **Suspicious Patterns** | Shortening services, mailto forms, abnormal URLs |

---

## 🚀 Local Installation

Want to run it locally? Follow these steps:

```bash
# Clone the repository
git clone https://github.com/AsadAbbasdev/Phishing-URL-Detection-using-ML.git
cd Phishing-URL-Detection-using-ML

# Create virtual environment
python -m venv phishing_env
source phishing_env/bin/activate  # Linux/Mac
# or
phishing_env\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
🚢 Deployment
This app is deployed on Streamlit Community Cloud:

URL: phishing-url-detector-webapp.streamlit.app

Python Version: 3.10

Auto-deploys on every push to main branch

## 👨‍💻 About the Developer

**Asad Abbas**
- 🐙 **GitHub**: [@AsadAbbasdev](https://github.com/AsadAbbasdev)
- 📁 **Project**: [Phishing-URL-Detection-using-ML](https://github.com/AsadAbbasdev/Phishing-URL-Detection-using-ML)
- 📧 **Email**: [asadabbas.contact@gmail.com](mailto:asadabbas.contact@gmail.com)
- 💼 **LinkedIn**: [asad-abbas-it](https://www.linkedin.com/in/asad-abbas-it)

🤝 Contributing
Contributions are welcome! Feel free to:

🐛 Report bugs

💡 Suggest new features

🔧 Submit pull requests

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Dataset from Kaggle: Phishing Website Detector

Streamlit for amazing deployment platform

Scikit-learn community for ML tools

⭐ Support
If you find this project useful, please consider:

Giving a ⭐ on GitHub

Sharing with your network

Reporting issues

<div align="center"> <h3>🛡️ Stay Safe Online | Think Before You Click</h3> <p>Made with ❤️ for Cybersecurity</p> </div> ```