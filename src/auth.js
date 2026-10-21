// Offline classroom access gate, not server-side authentication.
// Digests avoid storing plaintext passwords, but the downloadable game can be modified.
const ACCOUNTS = Object.freeze({
  "user01": "18e532fdcfa25566d4ecdfeefb915233706b01d37805cc657dad852152de2fc1",
  "user02": "3e1a2aa66a04320ab287f607db916fb27f567e9806e8d59f25328ca27f635b8a",
  "user03": "404319eeb44f635bb5326488b14972ba0b5b35d61af17a415633d801d6aa3262",
  "user04": "55ecc1827ea3090cf116c38b9db05d3ee11d4dce67b921db30b78147dc28c0be",
  "user05": "b77d78319ba7de48d1ace55fdd908e1f93e31e08a69058f357198b9a878d7903",
  "user06": "06e006f3db0fb10f41627b510dd328c1765971fd0850b5f569542f722d167344",
  "user07": "b7dd4e28950d27f0bcfca4dda96c5d3ec7b1441281fcd9f4bdb0d0f24f927e49",
  "user08": "0ecf44a31c6fd19bdb9cc19d0796968f860fb3d2f90abd34f48b5ff8f957e243",
  "user09": "89d664b9b42dbd0408e814ead588576e2210cddeba262284689ab8a263fb153e",
  "user10": "d70a7fe752d5a1eab7807c3acf0b5214b8e949219b933e0d1c9470a0fdcc999d",
  "user11": "dda39a6a945863a876bac6ea5def1667dc2c12cd41b4021f7efbcef86e970d59",
  "user12": "a01a515fad8041ff02ce40b1f378b2dcdc53feb9b35bda6d93b9cf227b949e47",
  "user13": "0cba732d00e14aa7f32ae3d9a06fb9453f40aa9514c5d0c107dcb07604ebf7c3",
  "user14": "0648c7fa5f1ce16fcf07821c5663b32df6801c2f4e5e3991e56cffbcd166c136",
  "user15": "77d8e5a272157b49204c11da8b15caf02261ed684f7884e4922ccda940fe4c0e",
  "user16": "67575a207024085b1ea170604e4fa3eab412e13328657f58dd924030750fb3a0",
  "user17": "28dcd8f56d8e7f0822f46e9d0f8a7e9224309b09aacecabd1f2f3a47fb9456d2",
  "user18": "7634512f85c3d7e4367ea924789ca317891433f2a6d863747da683705298db22",
  "user19": "be27c94ed5fbe17bd471b6ffe036bd1b27ad5b75dcd4fc69a08d796171a3294c",
  "user20": "27ddc6111c04a478e1b5c6e6ac5f50045e7a3f523c28f916a807df3743588ef1",
  "user21": "5363ef47c81411e5e0c9d20de1b75900c0955e29a02361100d8b4aa96db0e3a8",
  "user22": "fc687a343da71d9acf2c6cec067c70e2191cec29ee64eb9f70773d71b4a7ca17",
  "user23": "733b32be92d5260d00dc9bf40fec31cf399f10e8931acd83c332e7bdf93a6ede",
  "user24": "1b7aa7b43f6eb8d13ab97b28c65e2cca85a8d615455ce7f0516b6514b3b1aec1",
  "user25": "7395489cef992b8115137ac0203de9f472d0f1c3a92224d027fd2f907c917e2f",
  "user26": "b8053dfc41307ad029d2f9ef8e64558262f7ee84dea64defe85b17d2de4614b1",
  "user27": "7167f4519991a076e984d3a0d3de06865d1841fd72d0e485c5670ad87a11e2b7",
  "user28": "b4f0f5edcd469587f82448528dd40c4b943d421272b024fff3102687c0137418",
  "user29": "e06f9edaefe35c04da82a87bea5a6a757320bd19bc0e85adf946cfc61717a5d2",
  "user30": "3f5ba2e85e04ab99b801892e0d42c68b5f959f83504202b74254a127b6daf782",
  "teacher01": "ffae93bf23954e81fe20e1aa77fb3f3ee9d1484693183d5ecafb727a86b6eb8a",
  "teacher02": "05cee4183e787cb1e45cf37b02143410999077cd8600b68266c8724cf91431f8",
  "teacher03": "1ddf91620043d7b67ebb9a381366bb4aa6c0a33edade713783a2aaa547dabb3d",
  "teacher04": "3402874d49780ac79c8115b653536147fc6fb2fa4bae4eac77221025cddd345c",
  "teacher05": "a67c6bc2514262404bf6e192ff27de4d35861679ee5a7856417c669eb162a5d2",
  "admin": "8b45bcdf0f354690b9fbf6dd42cc4148953d7dcc573e28165b4932b4af0527eb",
});
const SESSION_KEY = 'neura-island-user-v1';
let currentUser = null;
const isAccount = (user) => Object.prototype.hasOwnProperty.call(ACCOUNTS, user);

export function getUser() {
  return currentUser;
}

export function restoreSession() {
  try {
    const user = sessionStorage.getItem(SESSION_KEY);
    currentUser = isAccount(user) ? user : null;
  } catch {
    currentUser = null;
  }
  return currentUser;
}

export async function login(username, password) {
  const user = username.trim().toLowerCase();
  if (!isAccount(user)) return false;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(user + ':' + password));
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  if (hex !== ACCOUNTS[user]) return false;
  currentUser = user;
  try {
    sessionStorage.setItem(SESSION_KEY, user);
  } catch {
    // With storage blocked, login works until the page is reloaded.
  }
  return true;
}

export function logout() {
  currentUser = null;
  try {
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // Storage may be blocked.
  }
}
