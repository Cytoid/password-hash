// For a detailed explanation regarding each configuration property, visit:
// https://jestjs.io/docs/en/configuration.html

module.exports = {
  rootDir: 'src',
  cacheDirectory: '/tmp/jest_rs',
  testEnvironment: "node",
  transform: {
    "^.+\\.tsx?$": "ts-jest"
  },
};
