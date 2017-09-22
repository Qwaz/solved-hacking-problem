@register.filter(name='getme')
def getme(value, arg):
  return getattr(value, arg)

@register.filter(name='checknum')
def checknum(value):
  check(value)

@register.filter(name='listme')
def listme(value):
  return dir(value)

'''
{{ mrpoopy|listme }}
{{ mrpoopy|getme:'__flag__' }}
flag{wow_much_t3mplate}
'''
