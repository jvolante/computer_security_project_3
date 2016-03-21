import json
import hashlib
import itertools
import collections
import string as s
import re
import datetime
import time
import multiprocessing
import sys

digs = s.digits + s.letters

# Used to parse the username, salt and hash from the text file
parse_user_data = re.compile(r"(\w+):([\w\d]*):([a-f\d]+)")

# Dictionary containing common substitutions for letters in passwords
common_substitutions = {'a':"4@", 'b':'8', 'd':'6', 'f':'#', 'g':'9', 'k':'<', 'v':'<>', 't':'+', 'e':'3', 'h':'#', 'i':'1!', 'l':'1!', 'o':'0', 's':'$5', 'x':'%', 'c':'(', 'y':'?', 'q':'9'}

userfile = "pa3hashes.txt"
outputfile = "passwords.txt"

def get_user_data():
  usernames = []
  salts = set()
  hashes = []

  with open(userfile) as f:
    for match in parse_user_data.finditer(f.read()):
      usernames.append(match.group(1))
      salts.add(match.group(2))
      hashes.append(match.group(3))

  return usernames, salts, hashes


def change_cases(strings):
  for string in strings:

    yield string
    yield string[0].upper() + string[1:]

def make_substitutions(strings):
  """
  Algorithm that generates possible strings from common substitutions of
  letters used in passwords.
  """
  for string in strings:
    yield string
    for letter, subs in common_substitutions.iteritems():
      if letter in string:
        for s in subs:
          yield string.replace(letter, s)
          for x in make_substitutions([string.replace(letter, s)]):
            if x != string.replace(letter, s):
              yield x


def try_words(words):
  start_time = time.time()
  user_names, salts, hashes = get_user_data()

  # Get a set for faster comparison
  hash_set = set(hashes)

  # Keep track of which passwords have been found so we don't ouput them more than once
  found_passwords = set()

  for word in words:
    mixed_words = tuple(set(make_substitutions(change_cases([word]))))
    for mixed_word in mixed_words:
      for i in get_char_combinations():

        def foo():
          yield i + mixed_word
          yield mixed_word + i
          yield mixed_word

        for password in foo():
          for salt in salts:
            md5 = hashlib.md5()
            md5.update(password)
            md5.update(salt)
            hsh = md5.hexdigest()

            if hsh in hash_set and password not in found_passwords:
              index = hashes.index(hsh)
              found_passwords.add(password)

              #get formatted time
              timediff = time.time() - start_time
              m, s = divmod(timediff, 60)
              h, m = divmod(m, 60)
              s, milis = divmod(s * 1000, 1000)

              print user_names[index], password, "%i:%i:%i:%i" % (h, m, s, milis)
              sys.stdout.flush()


def get_char_combinations():
  c1 = 33
  c2 = 33

  while c2 < 127:
    while c1 < 127:
      yield chr(c1) + chr(c2)
      c1 += 1
    yield chr(c2)
    c2 += 1


def process_job(data):
  """
  Function that does any prep work before a worker starts processing jobs
  """
  try_words(data)


def main():
  """
  Loads the dictionary into memory, sets up a pool of worker processes
  and schedules jobs to crack passwords.
  """

  with open("words.json") as f:
    words = json.load(f)
    words = [w.encode("ASCII") for w in words]

  num_cores = multiprocessing.cpu_count()

  # Prepare jobs for each core
  if len(words) >= num_cores:
    jobs = []
    words_per_job = len(words) / num_cores
    for i in range(num_cores - 1):
      jobs.append(words[words_per_job * i : words_per_job * (i + 1)])

    jobs.append(words[words_per_job * (num_cores - 1):])

    # Set up processes to do work
    workers = multiprocessing.Pool(num_cores)
    workers.map(process_job, jobs)

  else:
    #if there are very few words don't go parallel
    process_job(words)

  print "Done"


if __name__ == '__main__':
  main()
