 import * as firebase from 'https://www.gstatic.com/firebasejs/11.5.0/firebase-app.js';
import * as firestore from 'https://www.gstatic.com/firebasejs/11.5.0/firebase-firestore.js';
import { twofish } from 'twofish';

//initiallizing the firebase project and database
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
  //global variable that are used during a lot of the functions
  let currentUser=null; //current session user  
  let recipient=null; //the recipient that the chat is open on
  let userSignaturekeypair;    //the sinature keys
  let userEncryptionKeypair; //the ecnryption keys

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

//html elements that are used for hints about the form requirements in sign/log-in form
  let usernameProblem=document.getElementById("username-problem");
  let passwordProblem=document.getElementById("password-problem");
  let confirmPasswordProblem= document.getElementById("confirm-password-problem");
  let problems=[usernameProblem,passwordProblem,confirmPasswordProblem];
//switching between the login and the sign-in page
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
                //generating the keys for the first time
                userSignaturekeypair=await generateSigningKeys();
                userEncryptionKeypair=await generateEncryptionKeys();

                
                await  firestore.setDoc(documentReference,{//creating the user,with his hashed password,and his public keys and encrypted private keys
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
                loadConvos();//loading the list of conversations that's gonna appear on the left side of the chat
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
            if(user.data().password!=arrayBufferToBase64(await hash(password,"SHA-256"))) {//checking the hashed password with the hashed input from the login
                problems.forEach(function(problem) {
                    problem.style.display="none";
                }
                );
                passwordProblem.innerHTML="*incorrect password";
                passwordProblem.style.display="block";
                return;
            }
            
            let publicKey=await importSigningPublicKey(user.data().signaturePublicKey);    //importing the keys for the current session after login
            let privateKey=await decryptSigningPrivateKey(user.data().encryptedSignaturePrivateKey,password);//decrypting the private keys after importing them
            userSignaturekeypair={publicKey,privateKey};


            privateKey=await decryptEncryptionPrivateKey(user.data().encryptedEncryptionPrivateKey,password);
            publicKey=await importEncryptionPublicKey(user.data().encryptionPublicKey);
            userEncryptionKeypair={publicKey,privateKey};


            currentUser=username;
            document.getElementById("login").style.display="none"
            document.getElementById("chat").style.display="flex"
            document.getElementById("current-user").textContent=username;

             loadConvos();//loading conversation that're gonna appear on the left side of the chat
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
         //making the formula(control bits) of the end-to-end encryption using the input(radios) from the popup form
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
     //handling hints for the input requirements when the users enters a false information
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
        }else{      //creating  conversations with the formula on both sides (user and recipient) on the database
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
        }else{//updating the conversation formula for the next message on the chat
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
        loadMessages();//import the past messages of the conversation and initialise a real-time listener to update the conversation with new messages
    }
    }
         });
        
    }


    //the send message function
 async function sendMessage() {//sennd messages and encrypting them before sending them

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
            message:await PGPencrypt(message,formula,userEncryptionKeypair.publicKey,userSignaturekeypair.privateKey),//encrypt the message before sending it
            timestamp: firestore.serverTimestamp()
        });
        await firestore.addDoc(firestore.collection(db,`users/${recipient}/conversations/${currentUser}/messages`),{//creating a duplicate for the message to send to the other user(duplicate of the conversation)
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



      async function loadMessages() {//load the past mesasges of the conversation and update the conversation with new messages that are sent in real-time
        let sentFrom = await firestore.getDoc(firestore.doc(db, 'users', recipient));
        let signaturePublicKey = await importSigningPublicKey(sentFrom.data().signaturePublicKey);//importing the compatible key
    
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
    
        
        const messageElements = new Map();
    
        firestore.onSnapshot(q, (snapshot) => {
          
            const docs = [...snapshot.docs].sort((a, b) => 
                a.data().timestamp?.seconds - b.data().timestamp?.seconds
            );
    
            
            if (messageElements.size === 0) {
                messagesDiv.innerHTML = "";
            }
    
            docs.forEach(async (doc) => {
                const data = doc.data();
                const id = doc.id;
    
                
                if (!messageElements.has(id)) {
                    const messageElement = document.createElement("div");
                    messagesDiv.appendChild(messageElement);
                    messageElements.set(id, messageElement);
                    
                    
                    await displayMessage(
                        signaturePublicKey,
                        data.sender,
                        data.message,
                        data.timestamp?.toDate(),
                        messageElement
                    );
                } 
                //handling timestamp (it can go undefined when the message is just sent)
                else if (!messageElements.get(id).querySelector(".date") && data.timestamp) {
                    // Just update the timestamp
                    const dateElement = document.createElement("div");
                    dateElement.classList.add("date");
                    dateElement.textContent = `${data.timestamp.toDate().toLocaleDateString()} ${data.timestamp.toDate().toLocaleTimeString()}`;
                    
                    
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
    async function displayMessage(signaturePublicKey, sender, encryptedPackage, timestamp, messageElement) {//displaying the message in the correct side of the conversation according to who sent it
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


async function loadConvos(){//loads the list of conversations that is gonna show on the left side of  the chat
        const q=firestore.query(firestore.collection(db,"users",currentUser,"conversations"),firestore.orderBy("timestamp","desc"));//searching for the conversations and ordering them by the last time chat
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








async function PGPencrypt(message,formula,encryptionPublicKey,signaturePrivateKey){//the big algorithm that do all the work
    let keySize;
    let key;
    let iv;
    let hashFunction;
    //extracting what algorithms to use according to the formula
    switch(formula[2]){//deciding the hash for the message (in the signature)
        case 1:hashFunction="SHA-256";
        break;
        case 2:hashFunction="SHA-284";
        break;
        case 3:hashFunction="SHA3-256"
        break;
    }
    switch(formula[1]){//key size for the encrypting algorithm
        case 1:keySize=256;
        break;
        case 2:keySize=192;
        break;
        case 3:keySize=128;
    }
    iv=await genereateIv();//generating hte initial vector
    switch(formula[0]){//generating the key and encrypting using the suited algorithm according to the formula
        case 1:key=await generateAesKeys(keySize);
                message=aesCtrEncrypt(message,key,iv);
        break;
        case 2:key=await generateTwofishKeys(keySize);
                message=twofishCtrEncrypt(message,key,iv);
        break;
    }
    let messageSignature=sign(await message,signaturePrivateKey,hashFunction);//signing the message
    key=rsaEncrypt(key,encryptionPublicKey);//encrypting the key with the recipient public key
    iv=rsaEncrypt(iv,encryptionPublicKey);//encrypting the iv with the recipient public key
    let keySignature=sign(await key,signaturePrivateKey,hashFunction);//signing the encrypted key
    let ivSignature=sign(await iv,signaturePrivateKey,hashFunction);//signing the encrypted iv
    let originalPackage={//marking the package to sign him,it also contains the formula,every message has
        formula:arrayBufferToBase64(formula),                       //his own formula so that when the conversation formula gets updated past message will still be able to get decrypted
        message:await message,
        messageSignature:await messageSignature,
        key:await key,
        keySignature:await keySignature,
        iv:await iv,
        ivSignature:await ivSignature
    }

    let packageSignature=await sign(stringifyDeterministic(originalPackage),signaturePrivateKey,"SHA-256");//signing the package
    let fullPackage={
        packageSignature:packageSignature,
        originalPackage:originalPackage
    }
    return fullPackage;//returning the package and his formula
}

async function PGPdecrypt(packageRecieved,encryptionPrivateKey,signaturePublicKey){
    let originalPackage=packageRecieved.originalPackage;
    let formula=new Uint8Array(base64ToArrayBuffer(originalPackage.formula));//extracting the formula from the package
    let keySize;
    let hashFunction;
   //getting the informations of the used algorithms in the message from the formula
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
 //veryifing the signatures fo the package ,key,iv,and message
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
    let iv=await rsaDecrypt(originalPackage.iv,encryptionPrivateKey);//decrypting the iv with the user private key
    let message;
    switch(formula[0]){
        case 1:
            key=await rsaDecryptAesKey(originalPackage.key,encryptionPrivateKey);//decrypting the key with the user private key
            message=await aesCtrDecrypt(originalPackage.message,key,iv);//decrypting the message using the key and iv.
        return message;//returning the message
        break;
        case 2:
            key=await rsaDecrypt(originalPackage.key,encryptionPrivateKey);
            message=twofishCtrDecrypt(originalPackage.message,key, iv);
        return message;
        break;
    }
    
    
}

//aes algorithms

async function aesCtrEncrypt(message, key, iv) {//decrypting with aes-ctr using key  and iv
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


async function aesCtrDecrypt(base64Ciphertext, key, iv) {//decrypting with aes-ctr using key and iv
    const ciphertext = base64ToArrayBuffer(base64Ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CTR", counter: iv, length: 64 },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  }


// Twofish algorithms

function twofishCtrEncrypt(message, key, iv) {//encrypting with twofish algorithm using key and iv
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
    
      for (let k = 15; k >= 0 && ++counter[k] === 0; k--);
    }
    
    return arrayBufferToBase64(ciphertext);
  }

async function twofishCtrDecrypt(base64Ciphertext, key, iv) {//decrypting with twofish algortithm using key and iv
    const ciphertext =base64ToArrayBuffer(base64Ciphertext);
    const tf = new twofish.Twofish(key);
    const decrypted = new Uint8Array(ciphertext.length);
    const counter = new Uint8Array(iv); 
  
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


async function generateAesKeys(keySize) {//generating the key for the aes encryption
    
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-CTR",
        length: keySize,
      },
      true, 
      ["encrypt", "decrypt"]
    );
  

    return  key;
  }
 async function genereateIv(){//generating the iv for both the encryption algorithms
    return crypto.getRandomValues(new Uint8Array(16));
 }



  function generateTwofishKeys(keySize) {//generating the key for the twofish encryption
    
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
                            


async function hash(text,algorithm) {//general function that hash the text using the according algorithm entered in parameters and returning the imprint
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

  
async function generateEncryptionKeys() {//generating the encryption public and private keys using RSA-OAEP
    return await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true, 
      ["encrypt", "decrypt"] 
    );
  }
  
  
  async function generateSigningKeys() {//generating the signature public and private keys using RSA-PSS
    return await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true, 
      ["sign", "verify"] 
    );
  }






 //exporting the public Keys
async function exportPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
  }
  
  // Export the private keys
  async function exportPrivateKey(privateKey) {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    return arrayBufferToBase64(exported);
  }



  // Import Public Key
async function importEncryptionPublicKey(base64Key) {//importing the public key of RSA-OAEP
    return await crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"] 
    );
  }
  
  async function importSigningPublicKey(base64Key) { //importing the public key of RSA-PSS
    return await crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["verify"] // Only verification allowed
    );
  }
  
  // Import Private Key
  async function importEncryptionPrivateKey(base64Key) {//imporitng the private key of RSA-OAEP
    return await crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"] // Only decryption allowed
    );
  }
  
  async function importSigningPrivateKey(base64Key) {//importing the private key of RSA-PSS
    return await crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(base64Key),
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["sign"] // Only signing allowed
    );
  }


  async function encryptPrivateKey(privateKey, password) {//encrypting the private key and then exporiting it 
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



  async function decryptEncryptionPrivateKey(encryptedData, password) {//decrypting the encryption private key and then importing it
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
    return importEncryptionPrivateKey(privateKeyBase64); 
  }



async function decryptSigningPrivateKey(encryptedData, password) {//decrypting the private key of signature and the importing it to use
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
  

  async function rsaEncrypt(key, publicKey) {//encrypting keys with public key of the recipient
    let keydata;//tranforming the key to the compatible form of data (arrayBuffer)
    if(key instanceof Uint8Array){//if the key is from the twofish algortihm
        keydata=key;
    }else{//if the key is from aes algorithm
        keydata=await crypto.subtle.exportKey("raw",key);
    }
    
    const ciphertext = await crypto.subtle.encrypt(//encrypting the key
      { name: "RSA-OAEP" },
      publicKey,
      keydata
    );
    return arrayBufferToBase64(ciphertext);//returning the encrypted key
  }



  async function rsaDecrypt(base64Ciphertext, privateKey) {//decrypting the encrypted twofish algorithm key with rsa private key of the user
    const ciphertext = base64ToArrayBuffer(base64Ciphertext);
    const decrypted = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      ciphertext
    );
    return decrypted;
  }

  async function rsaDecryptAesKey(base64Ciphertext, privateKey) {//decrypting the encrypted aes algorithm key with rsa private key of the user
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




  async function sign(message, privateKey, hashFunction) {//signing the text with private key of the user after hashing it with the selected algorithm
    
    const messageHash = await hash(message,hashFunction); 
  
    
    const signature = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 }, 
      privateKey,
      messageHash
    );
  
    return arrayBufferToBase64(signature);
  }


  async function verify(message, base64Signature, publicKey, hashFunction) {//verifiying the integrity of the text after hashing it with the same hash function selected for signing and comparing it the the signature
    const messageHash = await hash(message,hashFunction);
  
    const isValid = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 }, 
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


async function deriveAesKey(password, salt) {//makes a strong key from the password to encrypt the private keys before exporting them to the database
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
        iterations: 100000, 
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-CBC', length: 256 }, 
      false, // Not extractable
      ['encrypt', 'decrypt'] 
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
  
 
  
