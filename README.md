# CipherLab: GUI-Based Encryption and Decryption Tool

## Overview

**CipherLab** is a Python Tkinter-based tool for encrypting and decrypting text using algorithms such as AES, RSA, and Blowfish. It features language detection, text-to-speech, and customizable themes.

## Features

- **Encryption Algorithms**: AES, RSA, Blowfish
- **Language Detection**: Identifies language and confidence score with `langid`
- **Text-to-Speech**: Converts text to speech using `pyttsx3`
- **Customizable Themes**: Supports light and dark modes
- **File Handling**: Open and save text files
- **Undo/Redo**: Manage text modifications

## Installation

### Prerequisites
- **Python 3.x**: [Download Python](https://www.python.org/)
- **pip**: Included with Python

### Setup
```bash
git clone https://github.com/sailwalpranjal/CipherLab.git
cd CipherLab
pip install pycryptodome pyttsx3 langid
```

## Usage

### Run the Application
```bash
python CipherLab.py
```

### Interface
- **Input Text Area**: For text entry
- **Output Text Area**: Displays results
- **Log Area**: Shows logs and notifications
- **Theme Settings**: Adjust colors and themes
- **File Menu**: Open and save files
- **Edit Menu**: Undo and redo text modifications
- **Settings Menu**: Manage themes and dark mode
- **Help Menu**: Access user guides

### Operations
1. **Select Encryption Method**: Choose AES, RSA, or Blowfish.
2. **Enter Key**: Provide the encryption key.
3. **Encrypt/Decrypt**: Click the respective button.

### Additional Features
- **Detect Language**: Identify text language.
- **Speak Text**: Convert text to speech.

## Code Overview

The `CipherLab ` class in `CipherLab.py` handles:
- **UI Initialization**
- **Theme Management**
- **Encryption/Decryption**
- **File Operations**
- **Text Operations**
- **Language Detection**
- **Text-to-Speech**

## Future Work

We have exciting plans for CipherLab and welcome contributions to help us achieve these goals:

### 1. Additional Encryption Algorithms
- **Plan**: Integrate more encryption algorithms like ChaCha20 and Twofish.
- **Goal**: Provide users with a broader range of encryption options.

### 2. Enhanced User Interface
- **Plan**: Redesign the UI for better usability and aesthetics.
- **Goal**: Improve layout and navigation for a more intuitive experience.

### 3. Multi-Language Support
- **Plan**: Add support for multiple languages.
- **Goal**: Make the application accessible to a global audience.

### 4. Advanced Security Features
- **Plan**: Implement advanced security measures, including HSM integration.
- **Goal**: Enhance security and secure key storage.

### 5. Cloud Integration
- **Plan**: Enable cloud-based encryption and decryption services.
- **Goal**: Facilitate seamless access from various devices.

### 6. API Integration
- **Plan**: Develop an API for third-party applications to interact with CipherLab.
- **Goal**: Expand functionality and integration capabilities.

### 7. Performance Optimization
- **Plan**: Optimize performance for handling larger files and faster processes.
- **Goal**: Improve speed and efficiency of encryption and decryption.

### 8. Extended File Support
- **Plan**: Support additional file formats and types.
- **Goal**: Increase versatility in file handling.

### 9. User Feedback System
- **Plan**: Incorporate a feedback system for user suggestions and feature requests.
- **Goal**: Continuously improve based on user input.

## Contributing to CipherLab

We welcome your contributions! Follow these steps to get started:

### 1. Fork and Clone
- **Fork** the [CipherLab repository](https://github.com/sailwalpranjal/CipherLab).
- **Clone** your fork:
  ```bash
  git clone https://github.com/your-username/CipherLab.git
  cd CipherLab
  ```

### 2. Create a Branch
- **Create** a new branch:
  ```bash
  git checkout -b your-branch-name
  ```

### 3. Make Changes
- Implement your changes or features.
- **Stage** and **commit** your changes:
  ```bash
  git add .
  git commit -m "Your descriptive message"
  ```

### 4. Push and Pull Request
- **Push** your branch:
  ```bash
  git push origin your-branch-name
  ```
- Go to the [original repository](https://github.com/sailwalpranjal/CipherLab) and **open a pull request**.

### 5. Review and Update
- Address any feedback you receive.
- Keep your fork updated:
  ```bash
  git fetch upstream
  git merge upstream/main
  ```

Thank you for contributing!

## License

This project is licensed under the Custom License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions, contact [Pranjal Sailwal](mailto:pranjalsailwal09@gmail.com).

---
# This script is successfully running as of Mon Aug 26 13:48:23 UTC 2024
# This script is successfully running as of Mon Aug 26 14:34:14 UTC 2024
