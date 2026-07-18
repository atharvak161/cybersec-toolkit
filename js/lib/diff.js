/**
 * Text diff tool — line-based LCS diff (classic dynamic-programming
 * longest-common-subsequence approach). Pure logic.
 * Returns a list of { type: 'equal'|'add'|'remove', line: string }.
 */

export function diffLines(textA, textB) {
  const a = textA.split('\n');
  const b = textB.split('\n');
  const n = a.length;
  const m = b.length;

  // dp[i][j] = length of LCS of a[i..] and b[j..]
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const result = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      result.push({ type: 'equal', line: a[i] });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      result.push({ type: 'remove', line: a[i] });
      i++;
    } else {
      result.push({ type: 'add', line: b[j] });
      j++;
    }
  }
  while (i < n) { result.push({ type: 'remove', line: a[i] }); i++; }
  while (j < m) { result.push({ type: 'add', line: b[j] }); j++; }

  return result;
}

/** Summary counts for a diff result. */
export function diffSummary(diffResult) {
  return diffResult.reduce(
    (acc, entry) => {
      acc[entry.type]++;
      return acc;
    },
    { equal: 0, add: 0, remove: 0 }
  );
}
