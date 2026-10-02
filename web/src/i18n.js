// Strings for the two phone-facing pages (keypad and tap page). The admin page
// is English only. The first language in the browser's preference list that is
// translated here wins; anything else gets English.

const STRINGS = {
  en: {
    entry: 'Entry',
    locked: 'Locked',
    unlocked: 'Unlocked',
    wrongCode: 'Wrong code',
    lockUnreachable: 'Lock unreachable',
    tryAgain: 'Try again',
    checking: 'Checking…',
    clear: 'Clear',

    action: 'Action',
    passkey: 'Passkey',
    newPasskey: 'New passkey',
    confirm: 'Confirm with fingerprint',
    register: 'Register passkey',
    done: 'Done',
    saved: 'Passkey saved. You can close this page.',
    cancelled: 'Cancelled.',
    expired: 'Session expired. Tap the tag again.',
    nobodyAllowed: 'Nobody is allowed to run this action.',
    notAllowed: 'This passkey may not run this action.',
    notHome: 'Only available from the home network.',
    notVerified: 'Could not verify your identity.',
    invalidLink: 'This link is invalid or has expired.',
    tooMany: 'Too many attempts. Try again in a minute.',
    haDown: 'Home Assistant is not responding.',
    failed: 'Something went wrong. Try again.',
    offline: 'No connection.',
  },
  pl: {
    entry: 'Wejście',
    locked: 'Zamknięte',
    unlocked: 'Otwarte',
    wrongCode: 'Błędny kod',
    lockUnreachable: 'Zamek nieosiągalny',
    tryAgain: 'Spróbuj ponownie',
    checking: 'Sprawdzam…',
    clear: 'Wyczyść',

    action: 'Akcja',
    passkey: 'Passkey',
    newPasskey: 'Nowy passkey',
    confirm: 'Potwierdź odciskiem',
    register: 'Zarejestruj passkey',
    done: 'Wykonano',
    saved: 'Passkey zapisany. Możesz zamknąć tę stronę.',
    cancelled: 'Anulowano.',
    expired: 'Sesja wygasła. Przyłóż telefon do tagu ponownie.',
    nobodyAllowed: 'Nikt nie ma uprawnień do tej akcji.',
    notAllowed: 'Ten passkey nie ma uprawnień do tej akcji.',
    notHome: 'Dostępne tylko z sieci domowej.',
    notVerified: 'Nie udało się potwierdzić tożsamości.',
    invalidLink: 'Link jest nieważny lub wygasł.',
    tooMany: 'Za dużo prób. Spróbuj za minutę.',
    haDown: 'Home Assistant nie odpowiada.',
    failed: 'Coś poszło nie tak. Spróbuj ponownie.',
    offline: 'Brak połączenia.',
  },
};

export const lang =
  (navigator.languages?.length ? navigator.languages : [navigator.language ?? 'en'])
    .map((l) => l.slice(0, 2).toLowerCase())
    .find((l) => l in STRINGS) ?? 'en';

document.documentElement.lang = lang;

export const t = STRINGS[lang];
