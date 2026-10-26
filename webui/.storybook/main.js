const config = {
    stories: ['../src/**/*.stories.@(js|jsx|ts|tsx)'],

    addons: [
        '@storybook/addon-links', // is this used?
        '@storybook/addon-themes',
        'storybook-addon-mock',
    ],

    framework: '@storybook/angular',

    core: {
        disableTelemetry: true, // Disables telemetry
    },

    webpackFinal: async (webpackConfig) => {
        // "@angular-devkit/build-angular" 21.2.28 updated webpack to 5.112.0, which started to cause
        // "SB_BUILDER-WEBPACK5_0003 (WebpackCompilationError)" / "Conflict: Multiple assets emit
        // different content to the same filename *.js.map" errors when running Storybook.
        // Angular's webpack config sets devtool: false and adds its own SourceMapDevToolPlugin,
        // but Storybook overrides devtool with its own setting.
        // Webpack documentation (https://webpack.js.org/configuration/devtool/) says:
        // "Never use both the devtool option and plugin (i.e. SourceMapDevToolPlugin) together.
        // The devtool option adds the plugin internally so you would end up with the plugin applied twice."
        //
        // Disabling devtool in Storybook's webpack config resolves the conflict.
        webpackConfig.devtool = false
        return webpackConfig
    },
}

export default config
