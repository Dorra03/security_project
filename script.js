document.addEventListener('DOMContentLoaded', function () {
  const webcam = document.getElementById('webcam');
  const canvas = document.getElementById('canvas');
  const startBtn = document.getElementById('start-btn');
  const captureBtn = document.getElementById('capture-btn');
  const loginBtn = document.getElementById('login-btn');
  const generateKeyBtn = document.getElementById('generate-key-btn');
  const encryptBtn = document.getElementById('encrypt-btn');
  const decryptBtn = document.getElementById('decrypt-btn');
  const fileInput = document.getElementById('file-input');
  const logoutBtn = document.getElementById('logout-btn');

  const welcomeSection = document.getElementById('welcome-section');
  const loginSection = document.getElementById('login-section');
  const faceSection = document.getElementById('face-section');
  const fileSection = document.getElementById('file-section');

  const loginMessage = document.getElementById('login-message');
  const faceMessage = document.getElementById('face-message');
  const fileStatus = document.getElementById('file-status');

  let encryptionKey = null;

  startBtn.addEventListener('click', () => {
    welcomeSection.style.display = 'none';
    loginSection.style.display = 'flex';
  });

  loginBtn.addEventListener('click', async () => {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();

    if (!username || !password) {
      showMessage(loginMessage, 'Please enter both username and password', 'error');
      return;
    }

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();
      if (data.status === 'success') {
        loginSection.style.display = 'none';
        faceSection.style.display = 'flex';
        setupWebcam();
      } else {
        showMessage(loginMessage, data.error || 'Login failed', 'error');
      }
    } catch (error) {
      showMessage(loginMessage, 'Server error during login', 'error');
    }
  });

  function setupWebcam() {
    navigator.mediaDevices.getUserMedia({ video: true })
      .then((stream) => {
        webcam.srcObject = stream;
      })
      .catch((error) => {
        showMessage(faceMessage, 'Cannot access webcam', 'error');
      });
  }

  captureBtn.addEventListener('click', async () => {
    canvas.width = webcam.videoWidth;
    canvas.height = webcam.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(webcam, 0, 0, canvas.width, canvas.height);

    canvas.toBlob(async (blob) => {
      const formData = new FormData();
      formData.append('image', blob, 'face.jpg');

      try {
        const response = await fetch('/api/recognize', {
          method: 'POST',
          body: formData
        });

        const data = await response.json();
        if (data.status === 'success') {
          showMessage(faceMessage, 'Face authenticated successfully!', 'success');
          setTimeout(() => {
            faceSection.style.display = 'none';
            fileSection.style.display = 'flex';
          }, 1500);
        } else {
          showMessage(faceMessage, data.error || 'Face not recognized', 'error');
        }
      } catch (error) {
        showMessage(faceMessage, 'Error during face recognition', 'error');
      }
    }, 'image/jpeg');
  });

  generateKeyBtn.addEventListener('click', () => {
    encryptionKey = crypto.getRandomValues(new Uint8Array(16)); // AES 128-bit key
    showMessage(fileStatus, 'Encryption key generated.', 'success');
  });

  encryptBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) {
      showMessage(fileStatus, 'Please select a file to encrypt.', 'error');
      return;
    }

    if (!encryptionKey) {
      showMessage(fileStatus, 'Generate an encryption key first.', 'error');
      return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = async () => {
      const fileData = new Uint8Array(reader.result);
      const iv = crypto.getRandomValues(new Uint8Array(16));

      try {
        const key = await crypto.subtle.importKey('raw', encryptionKey, 'AES-CBC', false, ['encrypt']);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, fileData);

        const blob = new Blob([iv, new Uint8Array(encrypted)], { type: 'application/octet-stream' });
        downloadBlob(blob, file.name + '.enc');

        showMessage(fileStatus, 'File encrypted successfully.', 'success');
      } catch (error) {
        showMessage(fileStatus, 'Encryption failed.', 'error');
      }
    };

    reader.readAsArrayBuffer(file);
  });

  decryptBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) {
      showMessage(fileStatus, 'Please select an encrypted file.', 'error');
      return;
    }

    if (!encryptionKey) {
      showMessage(fileStatus, 'No encryption key available.', 'error');
      return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = async () => {
      const buffer = new Uint8Array(reader.result);
      const iv = buffer.slice(0, 16);
      const encryptedData = buffer.slice(16);

      try {
        const key = await crypto.subtle.importKey('raw', encryptionKey, 'AES-CBC', false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, encryptedData);

        const blob = new Blob([decrypted], { type: 'application/octet-stream' });
        downloadBlob(blob, file.name.replace('.enc', '.dec'));

        showMessage(fileStatus, 'File decrypted successfully.', 'success');
      } catch (error) {
        showMessage(fileStatus, 'Decryption failed.', 'error');
      }
    };

    reader.readAsArrayBuffer(file);
  });

  logoutBtn.addEventListener('click', () => {
    stopWebcam();
    encryptionKey = null;
    fileInput.value = '';
    loginMessage.innerHTML = '';
    faceMessage.innerHTML = '';
    fileStatus.innerHTML = '';

    fileSection.style.display = 'none';
    welcomeSection.style.display = 'flex';
  });

  function stopWebcam() {
    const stream = webcam.srcObject;
    if (stream) {
      const tracks = stream.getTracks();
      tracks.forEach((track) => track.stop());
    }
    webcam.srcObject = null;
  }

  function showMessage(element, message, type) {
    element.textContent = message;
    element.className = type;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
});

