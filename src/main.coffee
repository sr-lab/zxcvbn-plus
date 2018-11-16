matching = require './matching'
scoring = require './scoring'
time_estimates = require './time_estimates'
feedback = require './feedback'

time = -> (new Date()).getTime()

zxcvbn_orig = (password, user_inputs = []) ->
  start = time()
  # reset the user inputs matcher on a per-request basis to keep things stateless
  sanitized_inputs = []
  for arg in user_inputs
    if typeof arg in ["string", "number", "boolean"]
      sanitized_inputs.push arg.toString().toLowerCase()
  matching.set_user_input_dictionary sanitized_inputs
  matches = matching.omnimatch password
  result = scoring.most_guessable_match_sequence password, matches
  result.calc_time = time() - start
  attack_times = time_estimates.estimate_attack_times result.guesses
  for prop, val of attack_times
    result[prop] = val
  result.feedback = feedback.get_feedback result.score, result.sequence
  result
  
# The following capital letter frequencies were calculated after stripping non-letters (for accuracy).

# Frequencies of capitals from start of string (only >5% included).
#
capsFromStartFreqs = [1.000000000, # No change to guess value if capital begins string (most common).
  0.607520934,
  0.595897093,
  0.564588646,
  0.523657789,
  0.433141195,
  0.280063826,
  0.175853428,
  0.098178584,
  0.055181003] # We assume any further from the start to be equivalent to this (difference negligible).

# Frequencies of capital from end of string (only >5% included).
#
capsFromEndFreqs = [0.633175298,
  0.607324515,
  0.601363930,
  0.597557488,
  0.573518191,
  0.523666963,
  0.348799951,
  0.227817787,
  0.127119202,
  0.0707041] # We assume any further from the end to be equivalent to this (difference negligible).

# Frequencies of symbols from start of string (only >5% included).
#
symbolFromStartFreqs = [0.265549375,
  0.238352608,
  0.220984679,
  0.313152474,
  0.388420797,
  0.499061992,
  0.500513332,
  0.411802049,
  0.328983689,
  0.244164538,
  0.133626228,
  0.100683203,
  0.072063553,
  0.054544579] # We assume any further from the start to be equivalent to this (difference negligible).

# Frequencies of symbols from end of string (only >5% included).
#
symbolFromEndFreqs = [1.000000000, # No change to guess value if symbol ends string (most common).
  0.433572159
  0.423187302
  0.386290850
  0.391535816
  0.312057949
  0.244400955
  0.203802819
  0.137835773
  0.117048547
  0.065995504
  0.073390117] # We assume any further from the end to be equivalent to this (difference negligible).

# Strips all non-alphabetic characters from a string.
#
# @param [String] str  the string to strip
#
stripNonAlpha = (str) ->
  str.replace(/[^a-zA-Z]/g, "")

# Returns true if the given character is an uppercase letter, otherwise returns false.
#
# @param [String] chr  the character
#
isUpperCase = (chr) ->
  code = chr.charCodeAt 0
  return (code > 64 && code < 91)

# Returns the locations of all capital letters in a string relative to its start and end.
#
# @param [String] str  the string to search
#
locateCaps = (str) ->
  caps = []
  stripped = stripNonAlpha str
  for i in [0...stripped.length]
    if isUpperCase stripped[i]
      caps.push [i, stripped.length - 1 - i]
  caps

# Returns true if the given character is a symbol, otherwise returns false.
#
# @param [String] chr  the character
#
isSymbol = (chr) ->
  code = chr.charCodeAt 0
  return !(code > 47 && code < 58) && !(code > 64 && code < 91) && !(code > 96 && code < 123)

# Returns the locations of all symbols in a string relative to its start and end.
#
# @param [String] str  the string to search
#
locateSymbols = (str) ->
  symbols = []
  for i in [0...str.length]
    if isSymbol str[i]
      symbols.push [i, str.length - 1 - i]
  symbols
  
# Returns the greater of two frequency indices for capital letters.
#
# @param [Array] pair  the pair of frequency indices
#
greatestCapFreq = (pair) ->
  Math.max indexOrLast(pair[0], capsFromStartFreqs), indexOrLast(pair[1], capsFromEndFreqs)

# Returns the value at the specified index in the given array or the last value in that array if out of bounds.
#
# @param [Integer] index    the index
# @param [Array] arr        the array
#
indexOrLast = (index, arr) ->
  if index < arr.length
    arr[index]
  else
    arr[arr.length - 1]
    
# Returns the greater of two frequency indices for symbols.
#
# @param [Array] pair  the pair of frequency indices
#
greatestSymbolFreq = (pair) ->
  Math.max indexOrLast(pair[0], symbolFromStartFreqs), indexOrLast(pair[1], symbolFromEndFreqs)
  
# Returns the least frequency given by a locator and valuer over a string.
#
# @param [Function] locator	the locator function
# @param [Function] valuer  the valuer function
# @param [String] str       the string
#
leastFreq = (locator, valuer, str) ->

  # No capitals? Then no change to guess value.
  caps = locator str
  if caps.length == 0 then return 1

  # Get minimum capital letter divisor.
  min = 1
  for i in [0...caps.length]
    min = Math.min min, valuer(caps[i])
  min
  
# Augments zxcvbn with some additional heuristics.
#
# @param [String] str  the string to provide to zxcvbn
#
zxcvbn = (password, user_inputs = []) ->

  # Get unadjusted results object.
  plain = zxcvbn_orig password, user_inputs

  # Adjust guesses.
  floatResult = plain.guesses
  floatResult /= leastFreq locateCaps, greatestCapFreq, password # Apply capital letters adjustment.
  floatResult /= leastFreq locateSymbols, greatestSymbolFreq, password # Apply symbols adjustment.

  # Apply corrections to results object.
  plain.guesses = Math.round floatResult
  plain.guesses_log10 = Math.log10 floatResult
  plain

module.exports = zxcvbn
