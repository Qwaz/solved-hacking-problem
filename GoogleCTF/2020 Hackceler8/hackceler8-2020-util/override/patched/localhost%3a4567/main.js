"use strict"

const RES_W = 1024  // Changing this breaks some CSS constants.
const RES_H = 576

let globals = {
  ws: null,  // WebSocket connection.
  visuals: null,  // Video rendering.
  res: null,  // Resource Manager.
  map: null,  // Current loaded map (if any).
  state: null,  // Current game state (if any).
  game: null,  // Game controller and main loop.
  main: null,  // Main object.
  ws_relay: null,
  custom: null,
  PORTAL_MOCK: false
}

const custom = {}
globals.custom = custom

custom.wsOnOpen = (e) => {
  // console.log("Web socket relay connected!")
}

custom.wsOnMessage = (e) => {
  new Response(e.data).arrayBuffer().then(buffer => {
    globals.game.auxiliaryInputQueue.push({
        type: "terminal",
        value: utils.uint8ArrayToHex(new Uint8Array(buffer))
    })
  })
}

custom.wsOnError = (e) => {
  console.log("custom.wsOnError", e)
}

custom.wsOnClose = (e) => {
  setTimeout(() => {
    custom.reconnect()
  }, 1000)
}

custom.reconnect = () => {
  if (globals.ws_relay instanceof WebSocket) {
    globals.ws_relay.close(4001, "Re-making connection for some reason.")
    globals.ws_relay = null
  }

  let ws_relay = new WebSocket("ws://localhost:9797")
  ws_relay.onopen = custom.wsOnOpen
  ws_relay.onmessage = custom.wsOnMessage
  ws_relay.onerror = custom.wsOnError
  ws_relay.onclose = custom.wsOnClose

  globals.ws_relay = ws_relay
}


const main = {}
globals.main = main

main.mockEnterShell = async (text) => {
  const eInput = document.getElementById("shell-input-v")
  eInput.value = ""

  let chars = text.split("")

  let promise = new Promise((resolve, reject) => {
    let intervalHandle = setInterval(() => {
      let char = chars.shift()

      if (char) {
        eInput.value += char
      } else {
        clearInterval(intervalHandle)
        resolve()
      }
    }, 200)
  })

  await promise
  eInput.value = ""
}

main.mockSleep = async (ms) => {
  let promise = new Promise((resolve, reject) => {
    setTimeout(() => { resolve() }, ms)
  })
  await promise
}

main.mockPlayTask = async () => {
  const e = document.getElementById("task-box")
  const eShell = document.getElementById("shell")
  e.style.display = "block"
}

main.showError = (text) => {
  const e = document.getElementById("error-box")
  e.innerText = text
  e.style.display = "block"
  e.style.opacity = "1"
}

main.hideError = () => {
  const e = document.getElementById("error-box")
  e.addEventListener("transitionend", () => {
    e.style.display = "none"
    e.innerText = ""
  }, { once: true })
  e.style.opacity = "0"
}

main.showLogin = () => {
  const e = document.getElementById("scene-login")
  e.style.display = "flex"
}

main.hideLogin = () => {
  const e = document.getElementById("scene-login")
  e.style.display = "none"
}

main.handleLogin = () => {
  const sceneEl = document.getElementById("scene-login")
  const username = sceneEl.querySelector("#username").value
  const password = sceneEl.querySelector("#password").value
  main.wsSend({
    type: "fullAuth",
    username: username,
    password: password
  })
}

main.wsSend = (data) => {
  if (globals.ws.readyState === 1) {
    globals.ws.send(JSON.stringify(data))
  } else {
    main.hideLogin()
    main.showError("Not connected yet, please retry.")
  }
}

main.wsOnOpen = (e) => {
  main.showError("Connected!")
  setTimeout(() => {
    main.hideError()
  }, 1000)
}

main.wsOnMessage = (e) => {
  let data = null
  try {
    data = JSON.parse(e.data)
  } catch(ex) {
    console.error("Failed to parse packet from server:", e.data)
    return
  }

  if (data.type === "startState") {
    globals.state = gameState.GameState.fromStateDict(data.state, globals.map)
    globals.game.start()
  }

  if (data.type === "plzAuth") {
    // Try fast-auth route.
    const fastToken = localStorage.getItem("fastToken")
    if (fastToken) {
      main.wsSend({
        type: "fastAuth",
        token: fastToken
      })
      return
    }

    // Fallback to re-login.
    main.showLogin()
  }

  if (data.type === "plzAuthFull") {
    // Fast authentication failed, so we have to fall-back to the normal route.
    // At the same time we can remove the token - it's useless.
    localStorage.removeItem("fastToken")
    main.showLogin()
  }

  if (data.type === "authOK") {
    if (data.hasOwnProperty("fastToken")) {
      localStorage.setItem("fastToken", data.fastToken)
    }
    main.showError("Logged in!")
    main.hideLogin()
  }

  if (data.type === "authFail") {
    main.showError("Login failed - wrong player id and/or password.")
  }

  if (data.type === "map") {
    let gameMap = new mapUtils.GameMap()
    gameMap.browserLoad(data.map)

    let a = document.createElement('a');
    document.body.appendChild(a);
    a.download = "tiles.js";
    a.href = "data:text/javascript;base64," + btoa("json="+JSON.stringify(data.map));
    a.click();

    globals.res.loadResources(gameMap.resources)
    .then(() => {
      globals.map = gameMap
      globals.visuals.initialize(globals.map)

      main.wsSend({
        type: "mapReady"
      })
    })
  }

  if (data.type === "terminal") {
    const terminalUI = globals.game.getTerminalUIObject(data.challengeID)

    const decodedData = data.data ? utils.hexToUint8Array(data.data) : null
    if (decodedData) {
      const text = utils.textDecoder.decode(decodedData)
      if (globals.ws_relay.readyState === 1) {
        globals.ws_relay.send(decodedData); 
      } else {
        console.log("Relay is disconnected. Run python script first.");
      }
      terminalUI.appendOutput(text)
      terminalUI.setStatus("connect")
    } else {
      terminalUI.setStatus(data.eventType)
    }
  }

  if (data.type === "precheckFlagResponse") {
    console.log(data);
    globals.game.processPrecheckFlagResponse(data)
  }
}

main.wsOnError = (e) => {
  console.log("wsOnError", e)
  globals.game.stop()
}

main.wsOnClose = (e) => {
  globals.game.stop()
  main.hideLogin()
  main.showError("Disconnected. Attempting to reconnect...")
  setTimeout(() => {
    main.reconnect()
  }, 500)
}

main.reconnect = () => {
  if (globals.ws instanceof WebSocket) {
    globals.ws.close(4001, "Re-making connection for some reason.")
    globals.ws = null
  }

  const loc = document.location
  const protocol = loc.protocol === "http:" ? "ws:" : "wss:"

  let ws = new WebSocket(`${protocol}//${loc.host}/`)
  ws.onopen = main.wsOnOpen
  ws.onmessage = main.wsOnMessage
  ws.onerror = main.wsOnError
  ws.onclose = main.wsOnClose

  globals.ws = ws

  custom.reconnect()
}

main.main = () => {
  globals.visuals = new visuals.Visuals()
  globals.res = new resourceManager.ResourceManager()
  globals.game = new game.Game()

  main.reconnect()

  const e = document.getElementById("login-submit")
  e.addEventListener("click", (ev) => {
    main.handleLogin()
    ev.preventDefault()
  })
}

main.onload = () => {
  main.main()
}

window.addEventListener("load", main.onload)
