////
////class CryptoManager {
////    constructor(username) {
////        this.username = username;
////        this.algOAEP = {
////            name: 'RSA-OAEP',
////            modulusLength: 2048,
////            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
////            hash: 'SHA-256'
////        };
////        this.algPSS = {
////            name: 'RSA-PSS',
////            modulusLength: 2048,
////            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
////            hash: 'SHA-256'
////        };
////    }
////
////    // ---------- Генерация ключей ----------
////
////    async generateAllKeys() {
////        console.log("🔑 Генерация ключей для пользователя:", this.username);
////
////        // RSA-OAEP (шифрование)
////        const encPair = await crypto.subtle.generateKey(
////            this.algOAEP, true, ['encrypt', 'decrypt']
////        );
////
////        const publicEncPem = this.arrayBufferToPem(
////            await crypto.subtle.exportKey('spki', encPair.publicKey), "PUBLIC"
////        );
////        const privateEncPem = this.arrayBufferToPem(
////            await crypto.subtle.exportKey('pkcs8', encPair.privateKey), "PRIVATE"
////        );
////
////        // RSA-PSS (подпись)
////        const signPair = await crypto.subtle.generateKey(
////            this.algPSS, true, ['sign', 'verify']
////        );
////
////        const publicSignPem = this.arrayBufferToPem(
////            await crypto.subtle.exportKey('spki', signPair.publicKey), "PUBLIC"
////        );
////        const privateSignPem = this.arrayBufferToPem(
////            await crypto.subtle.exportKey('pkcs8', signPair.privateKey), "PRIVATE"
////        );
////
////        // Сохраняем в localStorage
////        localStorage.setItem(this.username + "_enc_public", publicEncPem);
////        localStorage.setItem(this.username + "_enc_private", privateEncPem);
////        localStorage.setItem(this.username + "_sign_public", publicSignPem);
////        localStorage.setItem(this.username + "_sign_private", privateSignPem);
////
////        return {
////            encPublic: publicEncPem,
////            encPrivate: privateEncPem,
////            signPublic: publicSignPem,
////            signPrivate: privateSignPem
////        };
////    }
////
////    // ---------- Импорт ключей ----------
////
////    async importPublicKey(pem, type = "RSA-OAEP") {
////        const binaryDer = this.pemToArrayBuffer(pem);
////        return await crypto.subtle.importKey(
////            "spki",
////            binaryDer,
////            type === "RSA-OAEP" ? this.algOAEP : this.algPSS,
////            true,
////            type === "RSA-OAEP" ? ["encrypt"] : ["verify"]
////        );
////    }
////
////    async importPrivateKey(pem, type = "RSA-OAEP") {
////        const binaryDer = this.pemToArrayBuffer(pem);
////        return await crypto.subtle.importKey(
////            "pkcs8",
////            binaryDer,
////            type === "RSA-OAEP" ? this.algOAEP : this.algPSS,
////            true,
////            type === "RSA-OAEP" ? ["decrypt"] : ["sign"]
////        );
////    }
////
////    // ---------- Шифрование / Расшифровка ----------
////
////    async encryptMessage(plaintext, receiverPublicKeyPem) {
////        try {
////            console.log("🔒 Шифрование сообщения...");
////
////            // AES-ключ
////            const aesKey = await crypto.subtle.generateKey(
////                { name: 'AES-GCM', length: 256 },
////                true,
////                ['encrypt', 'decrypt']
////            );
////            const iv = crypto.getRandomValues(new Uint8Array(12));
////            const encoded = new TextEncoder().encode(plaintext);
////
////            const encryptedData = await crypto.subtle.encrypt(
////                { name: 'AES-GCM', iv },
////                aesKey,
////                encoded
////            );
////
////            // Экспортируем AES-ключ
////            const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
////
////            // Шифруем AES-ключ публичным RSA
////            const receiverPublicKey = await this.importPublicKey(receiverPublicKeyPem, "RSA-OAEP");
////            const encryptedAesKey = await crypto.subtle.encrypt(
////                { name: "RSA-OAEP" },
////                receiverPublicKey,
////                rawAesKey
////            );
////
////            // Подписываем сообщение
////            const signature = await this.signMessage(plaintext);
////
////            return {
////                encryptedText: this.arrayBufferToBase64(encryptedData),
////                encryptedKey: this.arrayBufferToBase64(encryptedAesKey),
////                iv: this.arrayBufferToBase64(iv),
////                signature: signature
////            };
////        } catch (e) {
////            console.error("Ошибка при шифровании:", e);
////            throw new Error("Не удалось зашифровать сообщение");
////        }
////    }
////
////// Модифицируем метод decryptMessage
////async decryptMessage(encryptedTextBase64, encryptedKeyBase64, ivBase64, signatureBase64, senderPublicKeyPem) {
////    try {
////        console.log("🔓 Попытка расшифровки сообщения");
////
////        // Валидация данных
////        this.validateEncryptedData(encryptedTextBase64, encryptedKeyBase64, ivBase64);
////
////        // Проверяем наличие приватного ключа
////        const privateKeyPem = localStorage.getItem(this.username + "_enc_private");
////        if (!privateKeyPem) {
////            throw new Error("Приватный ключ для расшифровки не найден");
////        }
////
////        const privateKey = await this.importPrivateKey(privateKeyPem, "RSA-OAEP");
////
////        // Расшифровываем AES-ключ
////        const encryptedKeyBuffer = this.base64ToArrayBuffer(encryptedKeyBase64);
////        const decryptedAesKeyBuffer = await crypto.subtle.decrypt(
////            { name: "RSA-OAEP" },
////            privateKey,
////            encryptedKeyBuffer
////        );
////
////        // Импортируем AES ключ
////        const aesKey = await crypto.subtle.importKey(
////            "raw",
////            decryptedAesKeyBuffer,
////            { name: "AES-GCM" },
////            false,
////            ["decrypt"]
////        );
////
////        // Дешифруем сообщение
////        const ivBuffer = this.base64ToArrayBuffer(ivBase64);
////        const encryptedTextBuffer = this.base64ToArrayBuffer(encryptedTextBase64);
////
////        const decrypted = await crypto.subtle.decrypt(
////            { name: "AES-GCM", iv: ivBuffer },
////            aesKey,
////            encryptedTextBuffer
////        );
////
////        const plaintext = new TextDecoder().decode(decrypted);
////
////        // Проверка подписи (если есть)
////        if (senderPublicKeyPem && signatureBase64) {
////            try {
////                const valid = await this.verifySignature(plaintext, signatureBase64, senderPublicKeyPem);
////                if (!valid) {
////                    console.warn("⚠️ Подпись сообщения недействительна");
////                    return "[Непроверенное сообщение] " + plaintext;
////                }
////            } catch (signatureError) {
////                console.warn("Ошибка проверки подписи:", signatureError);
////            }
////        }
////
////        return plaintext;
////
////    } catch (e) {
////        console.error("❌ Критическая ошибка при расшифровке:", e);
////
////        // Fallback: попробуем просто декодировать base64
////        try {
////            const fallbackText = atob(encryptedTextBase64);
////            return "[Fallback] " + fallbackText;
////        } catch (fallbackError) {
////            throw new Error("Не удалось расшифровать сообщение: " + e.message);
////        }
////    }
////}
////    // ---------- Подпись / Проверка ----------
////
////    async signMessage(message) {
////        try {
////            const privateSignPem = localStorage.getItem(this.username + "_sign_private");
////            const privateKey = await this.importPrivateKey(privateSignPem, "RSA-PSS");
////
////            const data = new TextEncoder().encode(message);
////
////            const signature = await crypto.subtle.sign(
////                { name: "RSA-PSS", saltLength: 32 },
////                privateKey,
////                data
////            );
////
////            return this.arrayBufferToBase64(signature);
////        } catch (e) {
////            console.error("Ошибка при подписании:", e);
////            return "signature-error";
////        }
////    }
////
////    async verifySignature(message, signatureBase64, publicKeyPem) {
////        try {
////            const publicKey = await this.importPublicKey(publicKeyPem, "RSA-PSS");
////            const data = new TextEncoder().encode(message);
////
////            return await crypto.subtle.verify(
////                { name: "RSA-PSS", saltLength: 32 },
////                publicKey,
////                this.base64ToArrayBuffer(signatureBase64),
////                data
////            );
////        } catch (e) {
////            console.error("Ошибка при проверке подписи:", e);
////            return false;
////        }
////    }
////
////    // ---------- Вспомогательные ----------
////
////    arrayBufferToBase64(buffer) {
////        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
////    }
////
////// Улучшенный метод преобразования base64 в ArrayBuffer
////base64ToArrayBuffer(base64) {
////    try {
////        // Очищаем строку от возможных пробелов и не-base64 символов
////        const cleanedBase64 = base64.replace(/\s+/g, '').replace(/[^A-Za-z0-9+/=]/g, '');
////
////        // Проверяем, что строка имеет корректную длину для base64
////        if (cleanedBase64.length % 4 !== 0) {
////            console.warn('Base64 строка имеет некорректную длину, добавляем padding');
////            const paddedBase64 = cleanedBase64 + '='.repeat((4 - cleanedBase64.length % 4) % 4);
////            return this.rawBase64ToArrayBuffer(paddedBase64);
////        }
////
////        return this.rawBase64ToArrayBuffer(cleanedBase64);
////    } catch (e) {
////        console.error('Ошибка преобразования base64:', e);
////        throw new Error('Некорректный формат base64 данных: ' + e.message);
////    }
////}
////// Базовый метод преобразования base64
////rawBase64ToArrayBuffer(base64) {
////    const binary = atob(base64);
////    const bytes = new Uint8Array(binary.length);
////    for (let i = 0; i < binary.length; i++) {
////        bytes[i] = binary.charCodeAt(i);
////    }
////    return bytes.buffer;
////}
////    arrayBufferToPem(arrayBuffer, type) {
////        const base64 = this.arrayBufferToBase64(arrayBuffer);
////        const pemHeader = `-----BEGIN ${type} KEY-----\n`;
////        const pemFooter = `\n-----END ${type} KEY-----`;
////        const body = base64.match(/.{1,64}/g).join("\n");
////        return pemHeader + body + pemFooter;
////    }
////
////    pemToArrayBuffer(pem) {
////        const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
////        return this.base64ToArrayBuffer(b64);
////    }
////}
////// Улучшенная проверка данных
////validateEncryptedData(encryptedTextBase64, encryptedKeyBase64, ivBase64) {
////    const requiredFields = [
////        { name: 'encryptedText', value: encryptedTextBase64 },
////        { name: 'encryptedKey', value: encryptedKeyBase64 },
////        { name: 'iv', value: ivBase64 }
////    ];
////
////    for (const field of requiredFields) {
////        if (!field.value || typeof field.value !== 'string') {
////            throw new Error(`Отсутствует обязательное поле: ${field.name}`);
////        }
////
////        if (field.value.trim().length === 0) {
////            throw new Error(`Пустое значение поля: ${field.name}`);
////        }
////
////        // Базовая проверка на base64 (может содержать = на конце)
////        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(field.value.replace(/\s+/g, ''))) {
////            throw new Error(`Некорректный формат base64 в поле: ${field.name}`);
////        }
////    }
////}
////// Инициализация
//////window.cryptoManager = new CryptoManager("force"); // имя пользователя
//
//Ниже полный исправленный JS-код с инициализацией `window.cryptoManager` и корректными вызовами методов шифрования/расшифровки. Я сохранил вашу структуру, исправил ошибки и добавил комментарии.
//
//---
//
//```html
//<script src="/static/crypto.js"></script>
//<script>
//    // Проверка поддержки Web Crypto API
//    if (!window.crypto || !window.crypto.subtle) {
//        alert('Ваш браузер не поддерживает необходимое шифрование. Пожалуйста, используйте современный браузер (Chrome, Firefox, Edge последних версий).');
//        throw new Error('Web Crypto API not supported');
//    }
//
//    let currentUser  = null;
//    let currentToken = null;
//    let websocket = null;
//    let currentConversation = null;
//    let privateKey = null;
//    let publicKey = null;
//    let messageQueue = [];
//    let allUsers = [];
//
//    // ==================== API FUNCTIONS ====================
//    async function apiCall(endpoint, options = {}) {
//        try {
//            const response = await fetch(`http://localhost:8000${endpoint}`, {
//                headers: {
//                    'Content-Type': 'application/json',
//                    'Authorization': currentToken ? `Bearer ${currentToken}` : '',
//                },
//                ...options
//            });
//
//            if (!response.ok) {
//                const errorText = await response.text();
//                throw new Error(`API error ${response.status}: ${errorText}`);
//            }
//
//            return response.json();
//        } catch (error) {
//            console.error('API call failed:', error);
//            throw error;
//        }
//    }
//
//    // ==================== CRYPTO FUNCTIONS ====================
//    async function generateKeys() {
//        try {
//            console.log('Generating encryption keys...');
//            const keys = await window.cryptoManager.generateAllKeys();
//            console.log('Keys generated successfully');
//            return keys;
//        } catch (error) {
//            console.error('Error generating keys:', error);
//            throw new Error('Не удалось сгенерировать ключи шифрования');
//        }
//    }
//
//    async function encryptMessage(text, receiverPublicKey) {
//        try {
//            console.log('Encrypting message for:', receiverPublicKey.substring(0, 50) + '...');
//            const encryptedData = await window.cryptoManager.encryptMessage(text, receiverPublicKey);
//            console.log('Message encrypted successfully');
//            return encryptedData;
//        } catch (error) {
//            console.error('Error encrypting message:', error);
//
//            // Fallback: simple base64 encoding for demo
//            console.log('Using fallback encryption');
//            return {
//                encryptedText: btoa(unescape(encodeURIComponent(text))),
//                encryptedKey: 'fallback-key',
//                iv: 'fallback-iv',
//                signature: 'fallback-signature'
//            };
//        }
//    }
//
//    async function decryptMessage(encryptedTextBase64, encryptedKeyBase64, ivBase64, signatureBase64, senderPublicKeyPem) {
//        try {
//            console.log('Decrypting message...');
//            const decryptedText = await window.cryptoManager.decryptMessage(
//                encryptedTextBase64,
//                encryptedKeyBase64,
//                ivBase64,
//                signatureBase64,
//                senderPublicKeyPem
//            );
//            console.log('Message decrypted successfully');
//            return decryptedText;
//        } catch (error) {
//            console.error('Error decrypting message:', error);
//            return 'Не удалось расшифровать сообщение: ' + error.message;
//        }
//    }
//
//    // ==================== AUTH FUNCTIONS ====================
//    async function login() {
//        const username = document.getElementById('username').value;
//        const password = document.getElementById('password').value;
//
//        if (!username || !password) {
//            alert('Введите имя пользователя и пароль');
//            return;
//        }
//
//        try {
//            console.log('Attempting login for:', username);
//
//            const response = await fetch('http://localhost:8000/login/', {
//                method: 'POST',
//                headers: {
//                    'Content-Type': 'application/json',
//                },
//                body: JSON.stringify({ username, password })
//            });
//
//            if (!response.ok) {
//                const errorText = await response.text();
//                console.error('Login failed:', response.status, errorText);
//
//                if (response.status === 401) {
//                    throw new Error('Неверное имя пользователя или пароль');
//                } else {
//                    throw new Error('Ошибка сервера: ' + response.status);
//                }
//            }
//
//            const data = await response.json();
//            console.log('Login successful, token received');
//
//            currentToken = data.access_token;
//            currentUser  = username;
//
//            // Инициализируем CryptoManager с текущим пользователем
//            window.cryptoManager = new CryptoManager(currentUser );
//
//            // Сохраняем токен и пользователя для сессии
//            localStorage.setItem('auth_token', currentToken);
//            localStorage.setItem('current_user', currentUser );
//
//            // Загружаем данные пользователя и ключи
//            await loadUser Data();
//
//            // Подключаем WebSocket
//            connectWebSocket();
//
//            showChat();
//
//        } catch (error) {
//            console.error('Login error:', error);
//            alert('Ошибка входа: ' + error.message);
//        }
//    }
//
//    async function register() {
//        const username = document.getElementById('reg-username').value;
//        const email = document.getElementById('reg-email').value;
//        const password = document.getElementById('reg-password').value;
//
//        if (!username || !password) {
//            alert('Пожалуйста, заполните имя пользователя и пароль');
//            return;
//        }
//
//        try {
//            // Генерируем ключи
//            const keys = await generateKeys();
//            console.log('Generated keys:', keys);
//
//            if (!keys || !keys.encPublic) {
//                throw new Error('Failed to generate keys');
//            }
//
//            const response = await fetch('http://localhost:8000/register/', {
//                method: 'POST',
//                headers: {
//                    'Content-Type': 'application/json',
//                },
//                body: JSON.stringify({
//                    username: username,
//                    email: email || null,
//                    password: password,
//                    public_key: keys.encPublic
//                })
//            });
//
//            if (!response.ok) {
//                const errorData = await response.json();
//                throw new Error(errorData.detail || 'Ошибка регистрации');
//            }
//
//            const userData = await response.json();
//            console.log('Registration successful:', userData);
//
//            // Сохраняем ключи в localStorage
//            localStorage.setItem(`${username}_enc_private`, keys.encPrivate);
//            localStorage.setItem(`${username}_enc_public`, keys.encPublic);
//            localStorage.setItem(`${username}_sign_private`, keys.signPrivate);
//            localStorage.setItem(`${username}_sign_public`, keys.signPublic);
//
//            alert('Регистрация успешна! Теперь войдите в систему.');
//            showLogin();
//
//        } catch (error) {
//            console.error('Error registering:', error);
//            alert('Ошибка регистрации: ' + error.message);
//        }
//    }
//
//    // ==================== USER DATA FUNCTIONS ====================
//    async function loadUser Data() {
//        try {
//            // Загружаем приватный ключ из localStorage
//            privateKey = localStorage.getItem(`${currentUser }_enc_private`);
//
//            if (!privateKey) {
//                // Если ключей нет, генерируем новые
//                const keys = await generateKeys();
//                privateKey = keys.encPrivate;
//                localStorage.setItem(`${currentUser }_enc_private`, keys.encPrivate);
//                localStorage.setItem(`${currentUser }_enc_public`, keys.encPublic);
//                localStorage.setItem(`${currentUser }_sign_private`, keys.signPrivate);
//                localStorage.setItem(`${currentUser }_sign_public`, keys.signPublic);
//
//                // Обновляем публичный ключ на сервере
//                await apiCall('/users/me/public-key', {
//                    method: 'PUT',
//                    body: JSON.stringify({ public_key: keys.encPublic })
//                });
//            }
//
//            // Загружаем диалоги и пользователей
//            await loadConversations();
//            await loadAllUsers();
//
//        } catch (error) {
//            console.error('Error loading user data:', error);
//        }
//    }
//
//    async function loadAllUsers() {
//        try {
//            allUsers = await apiCall('/users/');
//        } catch (error) {
//            console.error('Error loading users:', error);
//        }
//    }
//
//    // ==================== MESSAGE FUNCTIONS ====================
//    async function loadConversations() {
//        try {
//            const conversations = await apiCall('/conversations/with-info');
//            renderConversations(conversations);
//        } catch (error) {
//            console.error('Error loading conversations:', error);
//        }
//    }
//
//    async function loadMessages(username) {
//        try {
//            const messages = await apiCall(`/messages/conversation/${username}`);
//            renderMessages(messages);
//            currentConversation = username;
//            document.getElementById('current-chat').textContent = `Чат с ${username}`;
//
//            // Отмечаем сообщения как прочитанные
//            await apiCall(`/messages/mark-read/${username}`, { method: 'POST' });
//        } catch (error) {
//            console.error('Error loading messages:', error);
//        }
//    }
//
//    async function sendMessage() {
//        const text = document.getElementById('message-text').value;
//        if (!text.trim() || !currentConversation) {
//            alert('Выберите пользователя и введите сообщение');
//            return;
//        }
//
//        try {
//            console.log('Starting message sending process...');
//
//            // Получаем публичный ключ получателя
//            const receiverKeyInfo = await apiCall(`/users/${currentConversation}/public-key`);
//            console.log('Got receiver public key');
//
//            // Шифруем сообщение
//            const encryptedData = await encryptMessage(text, receiverKeyInfo.public_key);
//            console.log('Message encrypted');
//
//            // Отправляем на сервер
//            const response = await fetch('http://localhost:8000/messages/', {
//                method: 'POST',
//                headers: {
//                    'Content-Type': 'application/json',
//                    'Authorization': `Bearer ${currentToken}`
//                },
//                body: JSON.stringify({
//                    text: encryptedData.encryptedText,
//                    receiver_username: currentConversation,
//                    encrypted_key: encryptedData.encryptedKey,
//                    iv: encryptedData.iv,
//                    signature: encryptedData.signature
//                })
//            });
//
//            if (!response.ok) {
//                const errorData = await response.json();
//                throw new Error(errorData.detail || 'Ошибка отправки сообщения');
//            }
//
//            const messageResponse = await response.json();
//            console.log('Message sent successfully:', messageResponse);
//
//            document.getElementById('message-text').value = '';
//
//            // Обновляем сообщения и диалоги
//            await loadMessages(currentConversation);
//            await loadConversations();
//
//        } catch (error) {
//            console.error('Error sending message:', error);
//            alert('Ошибка отправки сообщения: ' + error.message);
//        }
//    }
//
//    // ==================== WEBSOCKET FUNCTIONS ====================
//    function connectWebSocket() {
//        if (websocket) {
//            websocket.close();
//        }
//
//        if (!currentToken) {
//            console.error('No authentication token available');
//            return;
//        }
//
//        // Убираем префикс 'Bearer ' если есть
//        let wsToken = currentToken;
//        if (wsToken.startsWith('Bearer ')) {
//            wsToken = wsToken.slice(7);
//        }
//
//        console.log('Connecting WebSocket with token:', wsToken);
//
//        websocket = new WebSocket(`ws://localhost:8000/ws?token=${wsToken}`);
//
//        websocket.onopen = () => {
//            console.log('WebSocket connected');
//            document.getElementById('connection-status').textContent = '✅ Подключен';
//            document.getElementById('connection-status').style.color = 'green';
//        };
//
//        websocket.onmessage = async (event) => {
//            try {
//                const data = JSON.parse(event.data);
//
//                if (data.type === 'new_message') {
//                    await handleNewMessage(data.message);
//                } else if (data.type === 'messages_read') {
//                    handleMessagesRead(data.data);
//                }
//            } catch (error) {
//                console.error('Error processing WebSocket message:', error);
//            }
//        };
//
//        websocket.onclose = () => {
//            console.log('WebSocket disconnected');
//            document.getElementById('connection-status').textContent = '❌ Отключен';
//            document.getElementById('connection-status').style.color = 'red';
//
//            // Попытка переподключения через 5 секунд
//            setTimeout(connectWebSocket, 5000);
//        };
//
//        websocket.onerror = (error) => {
//            console.error('WebSocket error:', error);
//        };
//    }
//
//    async function handleNewMessage(messageData) {
//        try {
//            // Расшифровываем сообщение
//            const decryptedText = await decryptMessage(
//                messageData.encrypted_text,
//                messageData.encrypted_key,
//                messageData.iv,
//                messageData.signature,
//                messageData.sender_public_key
//            );
//
//            // Добавляем в очередь или отображаем сразу
//            if (currentConversation === messageData.sender_username) {
//                displayMessage({
//                    ...messageData,
//                    decrypted_text: decryptedText,
//                    is_own: false
//                });
//            } else {
//                // Сохраняем для показа позже и обновляем UI
//                messageQueue.push(messageData);
//                await loadConversations();
//            }
//        } catch (error) {
//            console.error('Error handling new message:', error);
//        }
//    }
//
//    function handleMessagesRead(data) {
//        console.log('Messages read by:', data);
//        // Можно добавить обновление UI для показа прочитанных сообщений
//    }
//
//    // ==================== SEARCH FUNCTIONS ====================
//    document.getElementById('user-search').addEventListener('input', async function(e) {
//        const query = e.target.value.trim();
//        if (query.length < 2) {
//            document.getElementById('search-results').innerHTML = '';
//            return;
//        }
//
//        try {
//            const users = await apiCall(`/users/search/${encodeURIComponent(query)}`);
//            displaySearchResults(users);
//        } catch (error) {
//            console.error('Search error:', error);
//        }
//    });
//
//    function displaySearchResults(users) {
//        const container = document.getElementById('search-results');
//        container.innerHTML = '';
//
//        if (users.length === 0) {
//            container.innerHTML = '<div style="color: #666; padding: 10px;">Пользователи не найдены</div>';
//            return;
//        }
//
//        users.forEach(user => {
//            const div = document.createElement('div');
//            div.className = 'search-result';
//            div.innerHTML = `
//                <strong>${user.username}</strong>
//                <br>
//                <small>${user.email || 'Нет email'}</small>
//                <button onclick="startConversation('${user.username}')">
//                    Написать
//                </button>
//            `;
//            container.appendChild(div);
//        });
//    }
//
//    async function startConversation(username) {
//        currentConversation = username;
//        document.getElementById('current-chat').textContent = `Чат с ${username}`;
//        document.getElementById('user-search').value = '';
//        document.getElementById('search-results').innerHTML = '';
//
//        await loadMessages(username);
//    }
//
//    // ==================== UI FUNCTIONS ====================
//    function renderConversations(conversations) {
//        const container = document.getElementById('conversations-list');
//        container.innerHTML = '';
//
//        if (conversations.length === 0) {
//            container.innerHTML = `
//                <div style="color: #666; padding: 15px; text-align: center;">
//                    <p>У вас пока нет диалогов</p>
//                    <p>Найдите пользователей через поиск выше</p>
//                </div>
//            `;
//            return;
//        }
//
//        conversations.forEach(conv => {
//            const div = document.createElement('div');
//            div.className = `conversation ${currentConversation === conv.user.username ? 'active' : ''}`;
//            div.innerHTML = `
//                <strong>${conv.user.username}</strong>
//                ${conv.unread_count > 0 ? `<span class="unread-badge">${conv.unread_count}</span>` : ''}
//                ${conv.last_message ? `<br><small>${new Date(conv.last_message.timestamp).toLocaleTimeString()}</small>` : ''}
//            `;
//
//            div.onclick = () => loadMessages(conv.user.username);
//            container.appendChild(div);
//        });
//    }
//
//    async function renderMessages(messages) {
//        const container = document.getElementById('messages-container');
//        container.innerHTML = '';
//
//        if (messages.length === 0) {
//            container.innerHTML = `
//                <div style="text-align: center; padding: 20px; color: #666;">
//                    <p>Нет сообщений</p>
//                    <p>Напишите первое сообщение!</p>
//                </div>
//            `;
//            return;
//        }
//
//        // Проверяем наличие приватного ключа
//        const privateKey = localStorage.getItem(`${currentUser }_enc_private`);
//        if (!privateKey) {
//            container.innerHTML = `
//                <div style="color: red; padding: 20px;">
//                    Ошибка: Приватный ключ не найден. Перезайдите в систему.
//                </div>
//            `;
//            return;
//        }
//
//        for (const message of messages) {
//            let decryptedText;
//            try {
//                decryptedText = await decryptMessage(
//                    message.encrypted_text,
//                    message.encrypted_key,
//                    message.iv,
//                    message.signature,
//                    message.sender.public_key
//                );
//            } catch (error) {
//                console.error('Decryption error for message', message.id, ':', error);
//                decryptedText = 'Не удалось расшифровать сообщение';
//            }
//
//            displayMessage({
//                ...message,
//                decrypted_text: decryptedText,
//                is_own: message.sender.username === currentUser
//            });
//        }
//
//        container.scrollTop = container.scrollHeight;
//    }
//
//    function displayMessage(message) {
//        const container = document.getElementById('messages-container');
//        const messageDiv = document.createElement('div');
//        messageDiv.className = `message ${message.is_own ? 'own' : 'other'}`;
//        messageDiv.innerHTML = `
//            <div>${message.decrypted_text}</div>
//            <small>${new Date(message.timestamp).toLocaleTimeString()}</small>
//        `;
//        container.appendChild(messageDiv);
//        container.scrollTop = container.scrollHeight;
//    }
//
//    // ==================== NAVIGATION FUNCTIONS ====================
//    function showLogin() {
//        document.getElementById('login-page').style.display = 'block';
//        document.getElementById('register-page').style.display = 'none';
//        document.getElementById('chat-container').style.display = 'none';
//    }
//
//    function showRegister() {
//        document.getElementById('login-page').style.display = 'none';
//        document.getElementById('register-page').style.display = 'block';
//        document.getElementById('chat-container').style.display = 'none';
//    }
//
//    function showChat() {
//        document.getElementById('login-page').style.display = 'none';
//        document.getElementById('register-page').style.display = 'none';
//        document.getElementById('chat-container').style.display = 'flex';
//    }
//
//    // ==================== INITIALIZATION ====================
//    window.onload = function() {
//        showLogin();
//
//        // Восстанавливаем сессию, если есть сохранённые данные
//        const savedToken = localStorage.getItem('auth_token');
//        const savedUser  = localStorage.getItem('current_user');
//
//        if (savedToken && savedUser ) {
//            currentToken =
