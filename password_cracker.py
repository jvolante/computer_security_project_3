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
common_substitutions = {'a':"4@", 'e':'38', 'b':'56', 'g':'5&', 'h':'#', 'i':'1!', 'l':'1!', 'o':'0', 's':'$'}

PREPEND_ITERATIONS = 100 #999999
userfile = "pa3hashes.txt"
outputfile = "passwords.txt"

def int2base(x, base):
  if x < 0: sign = -1
  elif x == 0: return digs[0]
  else: sign = 1
  x *= sign
  digits = []
  while x:
    digits.append(digs[x % base])
    x /= base
  if sign < 0:
    digits.append('-')
  digits.reverse()
  return ''.join(digits).rstrip("0")


def ascii_encode_dict(data):
    ascii_encode = lambda x: x.encode('ascii')
    return dict(map(ascii_encode, pair) for pair in data.items())


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


def mod_string_to_password(string):
  """
  Generator function that makes possible passwords from a root string
  """

  string = set(change_cases([string]))

  for output in make_substitutions(string):
    yield output
  
  for output in make_substitutions(append_and_prepend_ints(string)):
    yield output


def change_cases(strings):
  for string in strings:

    yield string

    for i, letter in enumerate(string):
      if letter in s.lowercase:
        yield string[0:i] + string[i].upper() + string[i + 1:]
      elif letter in s.uppercase:
        yield string[0:i] + string[i].lower() + string[i + 1:]

    yield string.upper()
    yield string.lower()


def append_and_prepend_ints(strings):
  for string in strings:
    for x in xrange(PREPEND_ITERATIONS):
      append = str(x)

      yield string + append
      yield append + string


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


def get_string_with_subs_for_letter(string, letter, subs):
  yield string

  all_indexes = [i for i, l in enumerate(string) if l == letter]

  for i in all_indexes:
    for s in subs:
      result = string[:]
      result[i] = s
      yield result

  for i in range(1, len(all_indexes)):
    for indexes in itertools.combinations(all_indexes, i):
      for s in subs:
        result = string[:]

        for i in indexes:
          result[i] = s

        yield result


def try_words(words):
  start_time = time.time()
  user_names, salts, hashes = get_user_data()

  #get a set for faster comparison
  hash_set = set(hashes)

  # Keep track of which passwords have been found so we don't ouput them more than once
  found_passwords = set()

  for word in words:
    for putitive_password in mod_string_to_password(word):
      for salt in salts:
        md5 = hashlib.md5()
        md5.update(putitive_password)
        md5.update(salt)
        hsh = md5.hexdigest()

        if hsh in hash_set and putitive_password not in found_passwords:
          index = hashes.index(hsh)
          found_passwords.add(putitive_password)

          #get formatted time
          timediff = time.time() - start_time
          m, s = divmod(timediff, 60)
          h, m = divmod(m, 60)
          s, milis = divmod(s * 1000, 1000)

          print user_names[index], putitive_password, "%i:%i:%i:%i" % (h, m, s, milis)
          sys.stdout.flush()


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
    words = json.load(f, object_hook=ascii_encode_dict)
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
