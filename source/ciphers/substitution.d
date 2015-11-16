module ciphers.substitution;

import std.algorithm;
import std.algorithm.iteration : permutations;
import std.typecons;
import std.range : zip, iota;
import std.conv : to;
import std.array;
import std.functional : memoize;

alias SubstitutionTable = dchar[dchar];
alias FrequencyTable = float[dchar];

class SubstitutionCipher
{
  static immutable FrequencyTable letterFrequencies;

  private string cipherText;
  private SubstitutionTable substitutionTable;

  static this() {
    letterFrequencies = [
                       'a': 8.167,
                       'b': 1.492,
                       'c': 2.782,
                       'd': 4.253,
                       'e': 12.702,
                       'f': 2.228,
                       'g':	2.015,
                       'h': 6.094,
                       'i': 6.966,
                       'j': 0.153,
                       'k': 0.772,
                       'l': 4.025,
                       'm': 2.406,
                       'n': 6.749,
                       'o': 7.507,
                       'p': 1.929,
                       'q': 0.095,
                       'r': 5.987,
                       's': 6.327,
                       't': 9.056,
                       'u': 2.758,
                       'v': 0.978,
                       'w': 2.361,
                       'x': 0.150,
                       'y': 1.974,
                       'z': 0.074,
                       ];
  }

  private this(string cipherText, SubstitutionTable table) {
    this.cipherText = cipherText;
    this.substitutionTable = table;
  }

  public string[] possiblePlaintexts() {
    SubstitutionTable[] tables = [substitutionTable];

    dchar[][float]sameFrequencyChars;

    foreach (k, v; fastLetterFrequency(cipherText)) {
      if (v !in sameFrequencyChars) {
        sameFrequencyChars[v] = [k];
      } else {
        sameFrequencyChars[v] ~= k;
      }
    }

    std.stdio.stdout.writeln(sameFrequencyChars, this.substitutionTable);

    return [cipher(cipherText, this.substitutionTable)];
  }

  public static string cipher(string cipherText, SubstitutionTable substitutionTable) {
    return cipherText
      .map!(c => (c in substitutionTable) ? substitutionTable[c] : c)
      .to!string;
  }

  unittest {
    string plainText = "abcdefghijklmnopqrstuvwxyz";
    string cipherText = "bcdefghijklmnopqrstuvwxyza";
    SubstitutionTable substitution = assocArray(zip(plainText, cipherText));

    assert(cipher(plainText ~ " abc", substitution) == cipherText ~ " bcd");
  }

  /**
   * Attempts to solve the substitution table for the given ciphertext
   */
  public static SubstitutionTable solveSubstitutionTable(string cipherText) {
    import std.regex;


    Tuple!(dchar, float)[] englishLetterCount;
    foreach (k,v; letterFrequencies) {
      englishLetterCount ~= tuple(k, cast(float)v);
    }

    sort!q{a[1] < b[1]}(englishLetterCount);

    Tuple!(dchar, float)[] cipherLetterCount;
    foreach (k, v; fastLetterFrequency(cipherText)) {
      cipherLetterCount ~= tuple(k, cast(float)v);
    }

    sort!q{a[1] < b[1]}(cipherLetterCount);

    return assocArray(zip(cipherLetterCount.map!(t => t[0]), englishLetterCount.map!(t => t[0])));
  }

  alias fastLetterFrequency = memoize!letterFrequency;
  public static FrequencyTable letterFrequency(string text) pure {
    int[dchar] letterCount;
    int totalLetters;
    string ignoredLetters = " \n\r\t";

    foreach (dchar ch; text) {
      if (ignoredLetters.canFind(ch)) {
        continue;
      }

      letterCount[ch]++;
      totalLetters++;
    }

    FrequencyTable result;

    foreach (k, v; letterCount) {
      result[k] = cast(float)v / cast(float)totalLetters;
    }

    return result;
  }

  public static SubstitutionCipher breakCipher(string cipherText) {
    return new SubstitutionCipher(cipherText, solveSubstitutionTable(cipherText));
  }
}
