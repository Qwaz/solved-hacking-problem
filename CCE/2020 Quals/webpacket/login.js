const encode = text => text.split('').map(x=>String.fromCharCode(x.charCodeAt(0) ^ 0x23)).join('')

window.onload = () => {
  var ws = new WebSocket(`ws://${location.hostname}:3100`)
  
  ws.onmessage = (event) => {
    let recData = JSON.parse(event.data)
    switch (recData.event) {
      case 'res':
        $('#loginHelp').html(recData.data)
        $('#loginHelp').css('display', 'block')
        break
      default:
    }
  }

  $('#submit').on('click', async () => {
    const id = $('#id').val()
    const pw = encode($('#pw').val())

    let sendData = {event: 'login', data: { id,pw }}
    ws.send(JSON.stringify(sendData))
    $('#id').val('')
    $('#pw').val('')
  })
}