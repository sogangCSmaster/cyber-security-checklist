export function run(userInput: string) {
  return eval(userInput);
}
export const heading = (page: any) => page.$eval("h1", (el: any) => el.textContent);
