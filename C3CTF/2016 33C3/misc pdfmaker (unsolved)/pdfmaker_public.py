#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import signal
import sys
from random import randint
import os, pipes
from shutil import rmtree
from shutil import copyfile
import subprocess

class PdfMaker:

  def cmdparse(self, cmd):
    fct = {
      'help': self.helpmenu,
      '?': self.helpmenu,
      'create': self.create,
      'show': self.show,
      'compile': self.compilePDF,
      'flag': self.flag
    }.get(cmd, self.unknown)
    return fct

  def handle(self):
    self.initConnection()
    print " Welcome to p.d.f.maker! Send '?' or 'help' to get the help. Type 'exit' to disconnect."
    instruction_counter = 0
    while(instruction_counter < 77):
      try:
        cmd = (raw_input("> ")).strip().split()
        if len(cmd) < 1:
           continue
        if cmd[0] == "exit":
          self.endConnection()
          return
        print self.cmdparse(cmd[0])(cmd)
        instruction_counter += 1
      except Exception, e:
        print "An Exception occured: ", e.args
        self.endConnection()
        break
    print "Maximum number of instructions reached"
    self.endConnection()

  def initConnection(self):
    cwd = os.getcwd()
    self.directory = cwd + "/tmp/" + str(randint(0, 2**60))
    while os.path.exists(self.directory):
      self.directory = cwd + "/tmp/" + str(randint(0, 2**60))
    os.makedirs(self.directory)
    flag = self.directory + "/" + "33C3" + "%X" % randint(0, 2**31) +  "%X" % randint(0, 2**31)
    copyfile("flag", flag)


  def endConnection(self):
    if os.path.exists(self.directory):
      rmtree(self.directory)

  def unknown(self, cmd):
    return "Unknown Command! Type 'help' or '?' to get help!"

  def helpmenu(self, cmd):
    if len(cmd) < 2:
      return " Available commands: ?, help, create, show, compile.\n Type 'help COMMAND' to get information about the specific command."
    if (cmd[1] == "create"):
      return (" Create a file. Syntax: create TYPE NAME\n"
              " TYPE: type of the file. Possible types are log, tex, sty, mp, bib\n"
              " NAME: name of the file (without type ending)\n"
              " The created file will have the name NAME.TYPE")
    elif (cmd[1] == "show"):
      return (" Shows the content of a file. Syntax: show TYPE NAME\n"
              " TYPE: type of the file. Possible types are log, tex, sty, mp, bib\n"
              " NAME: name of the file (without type ending)")
    elif (cmd[1] == "compile"):
      return (" Compiles a tex file with the help of pdflatex. Syntax: compile NAME\n"
              " NAME: name of the file (without type ending)")

  def show(self, cmd):
    if len(cmd) < 3:
      return " Invalid number of parameters. Type 'help show' to get more info."
    if not cmd[1] in ["log", "tex", "sty", "mp", "bib"]:
      return " Invalid file ending. Only log, tex, sty and mp allowed"

    filename = cmd[2] + "." + cmd[1]
    full_filename = os.path.join(self.directory, filename)
    full_filename = os.path.abspath(full_filename)

    if full_filename.startswith(self.directory) and os.path.exists(full_filename):
      with open(full_filename, "r") as file:
        content = file.read()
    else:
      content = "File not found."
    return content

  def flag(self, cmd):
    pass

  def create(self, cmd):
    if len(cmd) < 3:
      return " Invalid number of parameters. Type 'help create' to get more info."
    if not cmd[1] in ["log", "tex", "sty", "mp", "bib"]:
      return " Invalid file ending. Only log, tex, sty and mp allowed"

    filename = cmd[2] + "." + cmd[1]
    full_filename = os.path.join(self.directory, filename)
    full_filename = os.path.abspath(full_filename)

    if not full_filename.startswith(self.directory):
      return "Could not create file."

    with open(full_filename, "w") as file:
      print "File created. Type the content now and finish it by sending a line containing only '\q'."
      while 1:
        text = raw_input("");
        if text.strip("\n") == "\q":
          break
        write_to_file = True;
        for filter_item in ("..", "*", "/", "\\x"):
          if filter_item in text:
            write_to_file = False
            break
        if (write_to_file):
          file.write(text + "\n")
    return "Written to " + filename + "."

  def compilePDF(self, cmd):
    if (len(cmd) < 2):
      return " Invalid number of parameters. Type 'help compile' to get more info."
    filename = cmd[1] + ".tex"
    full_filename = os.path.join(self.directory, filename)
    full_filename = os.path.abspath(full_filename)
    if not full_filename.startswith(self.directory) or not os.path.exists(full_filename):
      return "Could not compile file."
    compile_command = "cd " + self.directory + " && pdflatex " + pipes.quote(full_filename)
    compile_result = subprocess.check_output(compile_command, shell=True)
    return compile_result

def signal_handler_sigint(signal, frame):
  print 'Exiting...'
  pdfmaker.endConnection()
  sys.exit(0)

if __name__ == "__main__":
  signal.signal(signal.SIGINT, signal_handler_sigint)

  pdfmaker = PdfMaker()
  pdfmaker.handle()
