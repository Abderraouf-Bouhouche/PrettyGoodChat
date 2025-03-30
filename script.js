import * as firebase from 'https://www.gstatic.com/firebasejs/11.5.0/firebase-app.js';
import * as firestore from 'https://www.gstatic.com/firebasejs/11.5.0/firebase-firestore.js';
import { twofish } from 'twofish';
const firebaseConfig = {

    apiKey: "AIzaSyDPcYyQE-WmQZovitECCfva7n6voYFUUhc",
  
    authDomain: "prettygoodchat.firebaseapp.com",
  
    projectId: "prettygoodchat",
  
    storageBucket: "prettygoodchat.firebasestorage.app",
  
    messagingSenderId: "52437475541",
  
    appId: "1:52437475541:web:3d17e0abe9141e9bd0825c"
  
  };
  const app=firebase.initializeApp(firebaseConfig);
  const db=firestore.getFirestore(app);
  let currentUser=null;    
  let recipient=null;
  let userSignaturekeypair;
  let userEncryptionKeypair;

/*
  _                    _             __ _____  _                 _        
 | |                  (_)           / // ____|(_)               (_)       
 | |      ___    __ _  _  _ __     / /| (___   _   __ _  _ __    _  _ __  
 | |     / _ \  / _` || || '_ \   / /  \___ \ | | / _` || '_ \  | || '_ \ 
 | |____| (_) || (_| || || | | | / /   ____) || || (_| || | | | | || | | |
 |______|\___/  \__, ||_||_| |_|/_/   |_____/ |_| \__, ||_| |_| |_||_| |_|
                 __/ |                             __/ |                  
                |___/                             |___/                   
*/


  let usernameProblem=document.getElementById("username-problem");
  let passwordProblem=document.getElementById("password-problem");
  let confirmPasswordProblem= document.getElementById("confirm-password-problem");
  let problems=[usernameProblem,passwordProblem,confirmPasswordProblem];

document.getElementById("sign-in-link").addEventListener("click", function() {
        if(document.getElementById("sign-in-link").innerHTML=="Sign In") {
            document.getElementById("login-title").innerHTML="Sign In"
            document.getElementById("login-text").innerHTML="Already have an account?"
            document.getElementById("form-button").innerHTML="Sign In"
            document.getElementById("sign-in-link").innerHTML="Log In"
            document.getElementById("confirm-password").className="enabled"
            problems.forEach(function(problem) {
                problem.style.display="none";
            }
            );
    }else{
        document.getElementById("login-title").innerHTML="Log In"
        document.getElementById("login-text").innerHTML="Don't have an account?"
        document.getElementById("form-button").innerHTML="Log In" 
        document.getElementById("sign-in-link").innerHTML="Sign In"
        document.getElementById("confirm-password").className="disabled"
        problems.forEach(function(problem) {
            problem.style.display="none";
        }
        );
    }
});
//this is to get the login and sign up data and register or log in the user
var form_button=document.getElementById("form-button")
form_button.addEventListener("click", async function() {
        
    var username=document.getElementById("username").value
    var password=document.getElementById("password").value
    var confirm_password=document.getElementById("confirm-password").value
    if(document.getElementById("form-button").innerHTML=="Sign In") {
            signIn(username,password,confirm_password)
        }else{
            logIn(username,password)
        }
    });


async function signIn(username,password,confirm_password){

            if(username=="" || password=="" || confirm_password=="") {
                problems.forEach(function(problem) {
                    problem.innerHTML="*please fill in all fields";
                    problem.style.display="block";
                });
           }else if (password != confirm_password) {
                problems.forEach(function(problem) {
                    problem.style.display="none";
                });
                confirmPasswordProblem.innerHTML="*passwords do not match";
                confirmPasswordProblem.style.display="block";
 
            }else if(password.length<8) {
                problems.forEach(function(problem) {
                    problem.style.display="none";
                }
                );
                passwordProblem.innerHTML="*password must be at least 8 characters";
                passwordProblem.style.display="block";
            }else{
                let documentReference=firestore.doc(db,'users',username);
                const userSearch=await firestore.getDoc(documentReference);
                if(userSearch.exists()) {
                    problems.forEach(function(problem) {
                        problem.style.display="none";
                    });
                    usernameProblem.innerHTML="*username already taken";
                    usernameProblem.style.display="block";
                    return;
                }
                userSignaturekeypair=await generateSigningKeys();
                userEncryptionKeypair=await generateEncryptionKeys();

                
                await  firestore.setDoc(documentReference,{
                        username: username,
                        password:arrayBufferToBase64(await hash(password,"SHA-256")),
                        signaturePublicKey:await exportPublicKey(userSignaturekeypair.publicKey),
                        encryptionPublicKey:await exportPublicKey(userEncryptionKeypair.publicKey),
                        encryptedSignaturePrivateKey:await encryptPrivateKey(userSignaturekeypair.privateKey,password),
                        encryptedEncryptionPrivateKey:await encryptPrivateKey(userEncryptionKeypair.privateKey,password)

                });


                currentUser=username;
                document.getElementById("login").style.display="none"
                document.getElementById("chat").style.display="flex"
                document.getElementById("current-user").textContent=username;
                loadConvos();
            };
 
}

async function logIn(username,password){

        if(username=="" || password=="") {
                problems.forEach(function(problem) {
                    problem.innerHTML="*please fill in all fields";
                    problem.style.display="block";
                }
                );
                confirmPasswordProblem.style.display="none";
                return;
            }
            var username=document.getElementById("username").value
            var password=document.getElementById("password").value
            let documentReference=firestore.doc(db,'users',username);
            let user=await firestore.getDoc(documentReference);
            if(!user.exists()) {
                problems.forEach(function(problem) {
                    problem.style.display="none";
                }
                );
                usernameProblem.innerHTML="*user does not exist";
                usernameProblem.style.display="block";
                return;
            }
            if(user.data().password!=arrayBufferToBase64(await hash(password,"SHA-256"))) {
                problems.forEach(function(problem) {
                    problem.style.display="none";
                }
                );
                passwordProblem.innerHTML="*incorrect password";
                passwordProblem.style.display="block";
                return;
            }
            
            let publicKey=await importSigningPublicKey(user.data().signaturePublicKey);    
            let privateKey=await decryptSigningPrivateKey(user.data().encryptedSignaturePrivateKey,password);
            userSignaturekeypair={publicKey,privateKey};


            privateKey=await decryptEncryptionPrivateKey(user.data().encryptedEncryptionPrivateKey,password);
            publicKey=await importEncryptionPublicKey(user.data().encryptionPublicKey);
            userEncryptionKeypair={publicKey,privateKey};


            currentUser=username;
            document.getElementById("login").style.display="none"
            document.getElementById("chat").style.display="flex"
            document.getElementById("current-user").textContent=username;

             loadConvos();
}




/*                                       _
                                         (_)              
_ __ ___    ___  ___  ___   __ _   __ _  _  _ __    __ _ 
| '_ ` _ \  / _ \/ __|/ __| / _` | / _` || || '_ \  / _` |
| | | | | ||  __/\__ \\__ \| (_| || (_| || || | | || (_| |
|_| |_| |_| \___||___/|___/ \__,_| \__, ||_||_| |_| \__, |
                             __/ |  __/ |            __/ |
                             |___/  |___/            |___/ 



*/



const sendButton=document.getElementById("send-button");
const addButton=document.getElementById("add-convo");

    //  Set up the conversation popup window when the plus button is pressed
    addButton.addEventListener("click",function(event){
        setupConversation();
    })
    //  Send the message when the button send is clicked
    sendButton.addEventListener("click",function(event){
        sendMessage();
    })
    //  Send the message when the enter key is pressed
    document.getElementById("message-input").addEventListener("keydown", function(event) {
            if(event.key==="Enter") {
                sendMessage();
            }
        });




 async function setupConversation() {
        let popupWindow=document.getElementById("popup");
        popupWindow.style.display="flex";
        let setupButton=document.getElementById("submitSetupButton");
        let closeButton=document.getElementById("closeSetupPopup");
        let tempoRecipient;
        let hashChoice=document.querySelector('input[name="hash"]:checked').value;
        let algorithmChoice=document.querySelector('input[name="algorithm"]:checked').value;
        let keySizeChoice=document.querySelector('input[name="keySize"]:checked').value;
        let formula=new Uint8Array(5);
        switch(hashChoice) {
            case "SHA-256":formula[2]=1;
            break;
            case "SHA-284":formula[2]=2;
            break;
            case "SHA3-256":formula[2]=3;
            break;
            default:formula[2]=1;
        }
        switch(algorithmChoice) {
            case "AES":formula[0]=1;
            break;
            case "TwoFish":formula[0]=2;
            break;
            default:formula[0]=1;
        }
        switch(keySizeChoice) {
            case "256":formula[1]=1;
            break;
            case "192":formula[1]=2;
            break;
            case "128":formula[1]=3;
            break;
            default:formula[1]=2;
        }
        let formulaString=arrayBufferToBase64(formula);
        closeButton.addEventListener("click", function() {
            document.getElementById("problem-recipient-input").style.display="none";
            popupWindow.style.display="none";
            return;
        });
        setupButton.addEventListener("click", async function() {
            tempoRecipient=document.getElementById("recipient-input").value;
       
        
        if(tempoRecipient=="") {
            document.getElementById("problem-recipient-input").innerHTML="*please enter a username";
            document.getElementById("problem-recipient-input").style.display="block";
        }
        else if(tempoRecipient==currentUser) {
            document.getElementById("problem-recipient-input").innerHTML="*you cannot send messages to yourself";
            document.getElementById("problem-recipient-input").style.display="block";
        }else{
        const documentReference=firestore.doc(db,"users",tempoRecipient);
        const user=await firestore.getDoc(documentReference);
        if(!user.exists()) {
            document.getElementById("problem-recipient-input").innerHTML=`*user ${tempoRecipient} does not exist`;
            document.getElementById("problem-recipient-input").style.display="block";
        }else{      
        const doc=firestore.doc(db,`users/${currentUser}/conversations`,tempoRecipient);
        const conversation=await firestore.getDoc(doc);
        if(!conversation.exists()) {
            firestore.setDoc(doc,{
                recipient: tempoRecipient,
                sender: currentUser,
                timestamp: firestore.serverTimestamp(),
                formula:formulaString
            });
        const doc2=firestore.doc(db,`users/${tempoRecipient}/conversations`,currentUser);
        firestore.setDoc(doc2,{
            recipient: currentUser,
            sender: tempoRecipient,
            timestamp: firestore.serverTimestamp(),
            formula:formulaString
        });
        }else{
            await firestore.updateDoc(doc,{
                formula:formulaString
            })
        const doc2=firestore.doc(db,`users/${tempoRecipient}/conversations`,currentUser);
            await firestore.updateDoc(doc2,{
                formula:formulaString
            })
        }
        recipient=tempoRecipient;
        document.getElementById("problem-recipient-input").style.display="none";
        popupWindow.style.display="none";
        document.getElementById("current-recipient").textContent=recipient;
        document.getElementById("right-side").style.display="block";
        loadMessages();
    }
    }
         });
        
    }


    //the send message function
 async function sendMessage() {

        let conversation=await firestore.getDoc(firestore.doc(db,`users/${currentUser}/conversations`,recipient));
        let formula= new Uint8Array(base64ToArrayBuffer(conversation.data().formula));

        let sendTo=await firestore.getDoc(firestore.doc(db,'users',recipient)); 
        let encryptionPublicKey=await importEncryptionPublicKey(sendTo.data().encryptionPublicKey);


        const messageInput=document.getElementById("message-input");
        let message=messageInput.value.trim();
                if(!message) return;
        await firestore.addDoc(firestore.collection(db,`users/${currentUser}/conversations/${recipient}/messages`),{
            sender: currentUser,
            recipient: recipient,
            message:await PGPencrypt(message,formula,userEncryptionKeypair.publicKey,userSignaturekeypair.privateKey),
            timestamp: firestore.serverTimestamp()
        });
        await firestore.addDoc(firestore.collection(db,`users/${recipient}/conversations/${currentUser}/messages`),{
            sender: currentUser,
            recipient:recipient,
            message:await PGPencrypt(message,formula,encryptionPublicKey,userSignaturekeypair.privateKey),
            timestamp:firestore.serverTimestamp()
        });
        let docSender=firestore.doc(db,`users/${currentUser}/conversations`,recipient);
        let docRecipient=firestore.doc(db,`users/${recipient}/conversations`,currentUser);
        await firestore.updateDoc(docSender,{
            timestamp: firestore.serverTimestamp()
        });
        await firestore.updateDoc(docRecipient,{
            timestamp: firestore.serverTimestamp()
        });
        messageInput.value="";
        messageInput.focus();
}



      async function loadMessages() {
        let sentFrom = await firestore.getDoc(firestore.doc(db, 'users', recipient));
        let signaturePublicKey = await importSigningPublicKey(sentFrom.data().signaturePublicKey);
    
        const messagesDiv = document.getElementById("messages");
        const q = firestore.query(
            firestore.collection(db, `users/${currentUser}/conversations/${recipient}/messages`),
            firestore.or(
                firestore.and(
                    firestore.where("recipient", "==", currentUser),
                    firestore.where("sender", "==", recipient)
                ),
                firestore.and(
                    firestore.where("sender", "==", currentUser),
                    firestore.where("recipient", "==", recipient)
                )
            ),
            firestore.orderBy("timestamp")
        );
    
        // Store messages in memory with their DOM elements
        const messageElements = new Map();
    
        firestore.onSnapshot(q, (snapshot) => {
            // Process all documents in order
            const docs = [...snapshot.docs].sort((a, b) => 
                a.data().timestamp?.seconds - b.data().timestamp?.seconds
            );
    
            // Clear only if it's the first load
            if (messageElements.size === 0) {
                messagesDiv.innerHTML = "";
            }
    
            docs.forEach(async (doc) => {
                const data = doc.data();
                const id = doc.id;
    
                // If we haven't created this message yet
                if (!messageElements.has(id)) {
                    const messageElement = document.createElement("div");
                    messagesDiv.appendChild(messageElement);
                    messageElements.set(id, messageElement);
                    
                    // Display immediately (timestamp might be undefined)
                    await displayMessage(
                        signaturePublicKey,
                        data.sender,
                        data.message,
                        data.timestamp?.toDate(),
                        messageElement
                    );
                } 
                // If timestamp was undefined but is now available
                else if (!messageElements.get(id).querySelector(".date") && data.timestamp) {
                    // Just update the timestamp
                    const dateElement = document.createElement("div");
                    dateElement.classList.add("date");
                    dateElement.textContent = `${data.timestamp.toDate().toLocaleDateString()} ${data.timestamp.toDate().toLocaleTimeString()}`;
                    
                    // Find where to insert the date based on sender
                    if (data.sender === currentUser) {
                        messageElements.get(id).appendChild(dateElement);
                    } else {
                        messageElements.get(id).insertBefore(dateElement, messageElements.get(id).firstChild);
                    }
                }
            });
    
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        });
    }
    
    // Modified displayMessage function
    async function displayMessage(signaturePublicKey, sender, encryptedPackage, timestamp, messageElement) {
        const message = await PGPdecrypt(encryptedPackage, 
            sender === currentUser ? userEncryptionKeypair.privateKey : userEncryptionKeypair.privateKey,
            sender === currentUser ? userSignaturekeypair.publicKey : signaturePublicKey
        );
    
        messageElement.className = sender === currentUser ? 'message-user' : 'message-recipient';
        
        // Create message content
        const messageText = document.createElement("div");
        messageText.classList.add("message-text");
        messageText.textContent = message;
        
        if (sender !== currentUser) {
            messageText.style.background = "darkred";
        }
    
        // Add timestamp if available
        if (timestamp) {
            const dateElement = document.createElement("div");
            dateElement.classList.add("date");
            dateElement.textContent = `${timestamp.toLocaleDateString()} ${timestamp.toLocaleTimeString()}`;
            
            if (sender === currentUser) {
                messageElement.appendChild(messageText);
                messageElement.appendChild(dateElement);
            } else {
                messageElement.appendChild(dateElement);
                messageElement.appendChild(messageText);
            }
        } else {
            // Just add the message text if no timestamp yet
            messageElement.appendChild(messageText);
        }
    }


async function loadConvos(){
        const q=firestore.query(firestore.collection(db,"users",currentUser,"conversations"),firestore.orderBy("timestamp","desc"));
        firestore.onSnapshot(q,(snapshot)=>{
            const convoList=document.getElementById("chat-list");
            convoList.innerHTML="";
            snapshot.forEach((doc)=>{
                const convoElement=document.createElement("div");
                convoElement.classList.add("convo");
                convoElement.textContent=doc.data().recipient;
                convoElement.addEventListener("click",async function() {
                    recipient=doc.data().recipient;
                    document.getElementById("current-recipient").textContent=recipient;
                    document.getElementById("right-side").style.display="block";
                    loadMessages();
                });
                convoList.appendChild(convoElement);
                convoList.scrollTop=convoList.scrollHeight;
            });
      });
      }




   
 /*     ______                                   _    _               
      |  ____|                                 | |  (_)              
      | |__    _ __    ___  _ __  _   _  _ __  | |_  _   ___   _ __  
      |  __|  | '_ \  / __|| '__|| | | || '_ \ | __|| | / _ \ | '_ \ 
      | |____ | | | || (__ | |   | |_| || |_) || |_ | || (_) || | | |
      |______||_| |_| \___||_|    \__, || .__/  \__||_| \___/ |_| |_|
                                   __/ || |                          
                                  |___/ |_|                          
                                  */








async function PGPencrypt(message,formula,encryptionPublicKey,signaturePrivateKey){
    let keySize;
    let key;
    let iv;
    let hashFunction;
    switch(formula[2]){
        case 1:hashFunction="SHA-256";
        break;
        case 2:hashFunction="SHA-284";
        break;
        case 3:hashFunction="SHA3-256"
        break;
    }
    switch(formula[1]){
        case 1:keySize=256;
        break;
        case 2:keySize=192;
        break;
        case 3:keySize=128;
    }
    iv=await genereateIv();
    switch(formula[0]){
        case 1:key=await generateAesKeys(keySize);
                message=aesCtrEncrypt(message,key,iv);
        break;
        case 2:key=await generateTwofishKeys(keySize);
                message=twofishCtrEncrypt(message,key,iv);
        break;
    }
    let messageSignature=sign(await message,signaturePrivateKey,hashFunction);
    key=rsaEncrypt(key,encryptionPublicKey);
    iv=rsaEncrypt(iv,encryptionPublicKey);
    let keySignature=sign(await key,signaturePrivateKey,hashFunction);
    let ivSignature=sign(await iv,signaturePrivateKey,hashFunction);
    let originalPackage={
        formula:arrayBufferToBase64(formula),
        message:await message,
        messageSignature:await messageSignature,
        key:await key,
        keySignature:await keySignature,
        iv:await iv,
        ivSignature:await ivSignature
    }

    let packageSignature=await sign(stringifyDeterministic(originalPackage),signaturePrivateKey,"SHA-256");
    let fullPackage={
        packageSignature:packageSignature,
        originalPackage:originalPackage
    }
    return fullPackage;
}

async function PGPdecrypt(packageRecieved,encryptionPrivateKey,signaturePublicKey){
    let originalPackage=packageRecieved.originalPackage;
    let formula=new Uint8Array(base64ToArrayBuffer(originalPackage.formula));
    let keySize;
    let hashFunction;
    switch(formula[2]){
        case 1:hashFunction="SHA-256";
        break;
        case 2:hashFunction="SHA-284";
        break;
        case 3:hashFunction="SHA3-256";
        break;
    }
    switch(formula[1]){
        case 1:keySize=256;
        break;
        case 2:keySize=192;
        break;
        case 3:keySize=128;
        break;
    }
    if(! await verify(stringifyDeterministic(packageRecieved.originalPackage),packageRecieved.packageSignature,signaturePublicKey,"SHA-256")){
            console.error("package corrupted!");
        if(!await verify(originalPackage.key,originalPackage.keySignature,signaturePublicKey,hashFunction)){
            console.error("key file corrupted!");
        }
        if(! await verify(originalPackage.iv,originalPackage.ivSignature,signaturePublicKey,hashFunction)){
            console.error("iv file corrupted!");
        }
        if(!await verify(originalPackage.message,originalPackage.messageSignature,signaturePublicKey,hashFunction)){
            console.error("encrypted message corrupted!");
        }
        return;
    }
    let key;
    let iv=await rsaDecrypt(originalPackage.iv,encryptionPrivateKey);
    let message;
    switch(formula[0]){
        case 1:
            key=await rsaDecryptAesKey(originalPackage.key,encryptionPrivateKey);
            message=await aesCtrDecrypt(originalPackage.message,key,iv);
            console.log(message)
        return message;
        break;
        case 2:
            key=await rsaDecrypt(originalPackage.key,encryptionPrivateKey);
            message=twofishCtrDecrypt(originalPackage.message,key, iv);
        return message;
        break;
    }
    
    
}

//aes algorithms

async function aesCtrEncrypt(message, key, iv) {
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-CTR",
        counter: iv,          // 16-byte IV
        length: 64            // Counter length (bits)
      },
      key,                    // CryptoKey object
      new TextEncoder().encode(message) // String -> Uint8Array
    );
    return arrayBufferToBase64(new Uint8Array(ciphertext));
  }


async function aesCtrDecrypt(base64Ciphertext, key, iv) {
    const ciphertext = base64ToArrayBuffer(base64Ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CTR", counter: iv, length: 64 },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }


// Twofish algorithms

function twofishCtrEncrypt(message, key, iv) {
    const tf = new twofish.Twofish(key);
    const data = typeof message=== 'string' 
      ? new TextEncoder().encode(message) 
      : message;
    
    const ciphertext = new Uint8Array(data.length);
    const counter = new Uint8Array(iv); // Clone IV
    
    for (let i = 0; i < data.length; i += 16) {
      const keystream = tf.encrypt(counter);
      for (let j = 0; j < 16 && i + j < data.length; j++) {
        ciphertext[i + j] = data[i + j] ^ keystream[j];
      }
      // Increment counter (big-endian)
      for (let k = 15; k >= 0 && ++counter[k] === 0; k--);
    }
    
    return arrayBufferToBase64(ciphertext);
  }

async function twofishCtrDecrypt(base64Ciphertext, key, iv) {
    const ciphertext =base64ToArrayBuffer(base64Ciphertext);
    const tf = new twofish.Twofish(key);
    const decrypted = new Uint8Array(ciphertext.length);
    const counter = new Uint8Array(iv); // Clone IV
  
    for (let i = 0; i < ciphertext.length; i += 16) {
      const keystream = tf.encrypt(counter);
      for (let j = 0; j < 16 && i + j < ciphertext.length; j++) {
        decrypted[i + j] = ciphertext[i + j] ^ keystream[j];
      }
      for (let k = 15; k >= 0 && ++counter[k] === 0; k--);
    }
  
    return new TextDecoder().decode(decrypted);
  }


//  keys generators


async function generateAesKeys(keySize) {
    // 256-bit key (32 bytes)
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-CTR",
        length: keySize,
      },
      true, // Extractable
      ["encrypt", "decrypt"]
    );
  

    return  key;
  }
 async function genereateIv(){
    return crypto.getRandomValues(new Uint8Array(16));
 }



  function generateTwofishKeys(keySize) {
    // 256-bit key (32 bytes)
    const key = crypto.getRandomValues(new Uint8Array(keySize/8));
  
  
    return  key;
  }
                                                               
 /* _    _              _     
 | |  | |            | |    
 | |__| |  __ _  ___ | |__  
 |  __  | / _` |/ __|| '_ \ 
 | |  | || (_| |\__ \| | | |
 |_|  |_| \__,_||___/|_| |_|
   */                         
                            


async function hash(text,algorithm) {
    //  Convert password to a byte array
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
  
    //  Generate hash using SHA-256
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
  
    //  Convert hash to a hexadecimal string
 
    return hashBuffer; 
  }



  /*_____    _____          
  |  __ \  / ____|   /\    
  | |__) || (___    /  \   
  |  _  /  \___ \  / /\ \  
  | | \ \  ____) |/ ____ \ 
  |_|  \_\|_____//_/    \_\
 */

  // Generate Encryption Key Pair (RSA-OAEP)
async function generateEncryptionKeys() {
    return await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true, // Extractable
      ["encrypt", "decrypt"] // Strict usage
    );
  }
  
  // Generate Signing Key Pair (RSA-PSS)
  async function generateSigningKeys() {
    return await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true, // Extractable
      ["sign", "verify"] // Strict usage
    );
  }






  // Export Public Key (SPKI format)
async function exportPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
  }
  
  // Export Private Key (PKCS#8 format)
  async function exportPrivateKey(privateKey) {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    return arrayBufferToBase64(exported);
  }



  // Import Public Key
async function importEncryptionPublicKey(base64Key) {
    return await crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"] // Only encryption allowed
    );
  }
  
  async function importSigningPublicKey(base64Key) {
    return await crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["verify"] // Only verification allowed
    );
  }
  
  // Import Private Key
  async function importEncryptionPrivateKey(base64Key) {
    return await crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"] // Only decryption allowed
    );
  }
  
  async function importSigningPrivateKey(base64Key) {
    return await crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["sign"] // Only signing allowed
    );
  }


  async function encryptPrivateKey(privateKey, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await deriveAesKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    
    const exportedKey = await exportPrivateKey(privateKey);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      aesKey,
      new TextEncoder().encode(exportedKey)
    );
  
    return {
      encryptedKey: arrayBufferToBase64(encrypted),
      iv: arrayBufferToBase64(iv),
      salt: arrayBufferToBase64(salt)
    };
  }



  async function decryptEncryptionPrivateKey(encryptedData, password) {
    const aesKey = await deriveAesKey( 
      password,
      base64ToArrayBuffer(encryptedData.salt)
    );
  
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: base64ToArrayBuffer(encryptedData.iv) },
      aesKey,
      base64ToArrayBuffer(encryptedData.encryptedKey)
    );
  
    const privateKeyBase64 = new TextDecoder().decode(decrypted);
    return importEncryptionPrivateKey(privateKeyBase64); // or importSigningPrivateKey
  }



async function decryptSigningPrivateKey(encryptedData, password) {
    const aesKey = await deriveAesKey(
      password,
      base64ToArrayBuffer(encryptedData.salt)
    );
  
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: base64ToArrayBuffer(encryptedData.iv) },
      aesKey,
      base64ToArrayBuffer(encryptedData.encryptedKey)
    );
  
    const privateKeyBase64 = new TextDecoder().decode(decrypted);
    return importSigningPrivateKey(privateKeyBase64); // or importSigningPrivateKey
  }
  

  async function rsaEncrypt(key, publicKey) {
    let keydata;
    if(key instanceof Uint8Array){
        keydata=key;
    }else{
        keydata=await crypto.subtle.exportKey("raw",key);
    }
    
    const ciphertext = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      keydata
    );
    return arrayBufferToBase64(ciphertext);
  }



  async function rsaDecrypt(base64Ciphertext, privateKey) {
    const ciphertext = base64ToArrayBuffer(base64Ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      ciphertext
    );
    return decrypted;
  }

  async function rsaDecryptAesKey(base64Ciphertext, privateKey) {
    const ciphertext = base64ToArrayBuffer(base64Ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      ciphertext
    );
    return crypto.subtle.importKey("raw",
        decrypted,
    {name:"AES-CTR"},
    true,
    ["encrypt","decrypt"]
);

    
  }




  async function sign(message, privateKey, hashFunction) {
    // 1. Hash the message using your existing function
    const messageHash = await hash(message,hashFunction); // Must return Uint8Array
  
    // 2. Encrypt the hash with private key (this is the signature)
    const signature = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 }, // Or "RSASSA-PKCS1-v1_5"
      privateKey,
      messageHash
    );
  
    return arrayBufferToBase64(signature);
  }


  async function verify(message, base64Signature, publicKey, hashFunction) {
    // 1. Hash the original message
    const messageHash = await hash(message,hashFunction);
  
    // 2. Decrypt the signature (extract expected hash)
    const isValid = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 }, // Must match signing algorithm
      publicKey,
      base64ToArrayBuffer(base64Signature),
      messageHash
    );
  
    return isValid;
  }


  /*_    _        _                         
  | |  | |      | |                        
  | |__| |  ___ | | _ __    ___  _ __  ___ 
  |  __  | / _ \| || '_ \  / _ \| '__|/ __|
  | |  | ||  __/| || |_) ||  __/| |   \__ \
  |_|  |_| \___||_|| .__/  \___||_|   |___/
                   | |                     
                   |_|                     
*/


async function deriveAesKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
  
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000, // Security parameter (NIST recommended minimum)
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-CBC', length: 256 }, // 256-bit key
      false, // Not extractable
      ['encrypt', 'decrypt'] // Key usages
    );
  }


function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }
 

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }



  function stringifyDeterministic(obj) {
    return JSON.stringify(obj, Object.keys(obj).sort());
  }
  
 
  