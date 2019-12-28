import ast
import asyncio
import websockets
import json
from LCPkeyManagement import keyManagement as keys
from LCPkeyManagement import Addresses as addresses
import base64

async def connection(uri="ws://13.59.6.90"):
    async with websockets.connect(uri) as websocket:
        while True:
            message = await websocket.recv()
            await on_message(websocket, message)


async def on_message(websocket, incomingMessage):
    print("routing")
    toBeRouted = json.loads(incomingMessage)
    print(incomingMessage)
    if toBeRouted is None :
        pass
        #how to raise error without stopping functionality
    elif (toBeRouted[0] == "justsaying"):
        await manageJustSaying(websocket,toBeRouted)
    elif (toBeRouted[0] == "request"):
        print("request ",incomingMessage)


async def manageJustSaying(websocket, messageFromHub):
    message = messageFromHub[1]
    if (message["subject"] == "hub/challenge"):
        print("managing hub challenge ")
        print(message)
        challenge = message["body"]
        signature,pubkey = getSignature(challenge)
        loginMessage = {"challenge":challenge,"pubkey":pubkey,"signature":signature}
        await handleLoginChallenge(websocket, loginMessage) 
    else:
        print(messageFromHub)


async def sendJSmessage(websocket, content,route):
    print("content is ",content)
    message = {"subject":route,"body":content}
    messageArray = ["justsaying",message]
    print("message array is ",messageArray)
    messageStr = json.dumps(messageArray)
    await websocket.send(messageStr)
    
def getSignature(challenge):
    mKey = keys.generateMasterKey()
    dKey = mKey.generateDeviceKey()
    pbKeyBytes = dKey.key.public_key.compressed_bytes
    pbKeyb64 = base64.b64encode(pbKeyBytes)
    challengeObject = {"challenge":challenge,"pubkey":str(pbKeyb64,"utf-8")}
    challengeObjectStr = addresses._stringUtil(challengeObject)
    challengeBytes = bytearray(challengeObjectStr,"utf-8")
    challengeSHA256 = addresses._generateHash(challengeBytes,algorithm="sha256")
    signedChallenge = dKey.key.sign(challengeSHA256,do_hash=False).__bytes__()
    print("signature to der is ", signedChallenge)
    b64sig = base64.b64encode(signedChallenge)
    signatureStr = str(b64sig,"utf-8")
    print("signature length is ",len(signatureStr))
    print('signature string is ',signatureStr)
    return signatureStr, str(pbKeyb64,"utf-8")

async def handleLoginChallenge(websocket, loginMessage):
    await sendJSmessage(websocket,loginMessage,"hub/login")

loop = asyncio.get_event_loop()
asyncio.ensure_future(connection())
loop.run_forever()


