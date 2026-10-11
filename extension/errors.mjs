export class Refusal extends Error {
  constructor(reason, remedy = "read again", detail = {}) {
    super(reason);
    this.reason = reason;
    this.detail = { remedy, ...detail };
  }
}

export const DEADLINES = Object.freeze({ attach: 5000, dispatch: 5000, reply: 30000, chunk: 5000, cancel: 2000, hello: 5000 });

export function bounded(promise, phase, milliseconds = DEADLINES[phase]) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Refusal(`${phase}_deadline`)), milliseconds);
    }),
  ]).finally(() => clearTimeout(timer));
}
