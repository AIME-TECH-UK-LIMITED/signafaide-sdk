/** `1 record`, `2 records`: a count with its noun in the right number. */
export const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;
