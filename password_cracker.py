import json
import hashlib
import itertools
import collections
import string
import re
import datetime
import multiprocessing

digs = string.digits + string.letters

parse_user_data = re.compile(r"(\w)+:([\w\d]+):([a-f\d]+)")

#dictionary containing common substitutions for letters in passwords
common_substitutions = {'a':"4@", 'e':'38', 'g':'5', 'h':'#', 'i':'1!', 'l':'1!', 'o':'0', 's':'$'}

PREPEND_ITERATIONS = 99999999
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

  string = [string]

  for output in make_substitutions(string):
    yield output

  for output in prepend_chars(string):
    yield output

  for output in append_chars(string):
    yield output

  for output in make_substitutions(prepend_chars(string)):
    yield output

  for ouptut in make_substitutions(append_chars(string)):
    yield output

  for output in make_substitutions(prepend_chars(append_chars(string))):
    yield output


def prepend_chars(strings):
  """
  Generator function that prepends a sequence of numbers and letters to a list of strings
  """

  for string in strings:
    for x in itertools.islice(itertools.count(), 0, PREPEND_ITERATIONS):
      prepend = int2base(x, 36)
      # prepend = str(x)

      yield prepend + string


def append_chars(strings):
  """
  Generator function that appends a sequence of numbers and letters to a list of strings
  """

  for string in strings:
    for x in itertools.islice(itertools.count(), 0, PREPEND_ITERATIONS):
      append = int2base(x, 36)
      # append = str(x)

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
            yield x


def do_nothing(strings):
  """
  A bit of a hacky way to get instances where nothing happens to the strings
  """
  for string in strings:
    yield string


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
  start_time = datetime.time()
  user_names, salts, hashes = get_user_data()

  for word in words:
    for putitive_password in mod_string_to_password(word):
      for salt in salts:
        md5 = hashlib.md5()
        md5.update(putitive_password)
        md5.update(salt)
        hsh = md5.hexdigest()

        index = -1
        if hsh in hashes:
          index = hashes.index(hsh)

        if index != -1:
          timediff = datetime.time() - start_time
          print user_names[index], putitive_password, "%i:%i:%i:%i" % (diff.hours, diff.minutes, diff.seconds, diff.microseconds / 1000)


def process_job(data):
  print "Process started"
  try_words(data)


def main():
  with open("words.json") as f:
    words = json.load(f, object_hook=ascii_encode_dict)
    words = [w.encode("ASCII") for w in words]

  num_cores = multiprocessing.cpu_count()

  # Prepare jobs for each core
  jobs = []
  words_per_job = len(words) / num_cores
  for i in range(num_cores - 1):
    jobs.append(words[words_per_job * i : words_per_job * (i + 1)])

  jobs.append(words[words_per_job * (num_cores - 1):])

  # Set up processes to do work
  workers = multiprocessing.Pool(num_cores)
  workers.map(process_job, jobs)

  print "Done"


if __name__ == '__main__':
  main()
