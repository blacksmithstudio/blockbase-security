const CryptoJS = require('crypto-js')

/**
 * Blockbase Security Driver
 * @namespace app.drivers.security
 * @author Alexandre Pereira <alex@blacksmith.studio>
 * @param {Object} app - app namespace to update
 *
 * @returns {Object} controller
 */
module.exports = (app) => {
    if(!app.config.has('cryptokey'))
        return app.drivers.logger.error('Drivers', 'Cannot init security driver, no valid config')

    /**
     * extract token from an express res variable
     * @param {object} req - req from express
     * @returns {string|null} token or null
     */
    function extractToken(req){
        if(req.headers['authorization'])
            return req.headers['authorization'].split('Bearer ')[1]

        if(req.session && res.session.token)
            return req.session.token

        return null
    }

    return {
        /**
         * request processing sub methods (with express)
         * @memberof app.drivers.security
         */
        request : {
            /**
             * check if a req is eligible to authentication
             * by checking the presence of headers etc...
             * @memberof app.drivers.security.request
             * @param {Object} req - express normalized request
             * @param {Object} res - express normalized response
             * @param {boolean} strict - if strict will stop the process
             * @returns {Object} token data and check result
             */
            authenticable(req, res, strict = false){
                if(!req.data)
                    req.data = {
                        token : extractToken(req)
                    }

                if(!req.data.token && strict){
                    res.status(422).send({ error : 'Missing parameter : header authorization bearer token is required' })
                    return { data : req.data, check : false }
                }

                return { data : req.data, check : !req.data.token ? false : true }
            }
        },

        /**
         * token sub methods
         * @memberof app.drivers.security
         */
        token : {
            /**
             * encrypt the token
             * @memberof app.drivers.security.token
             * @param {*} content - content to put in the token
             * @returns {string} encrypted token
             */
            encrypt(content){
                return CryptoJS.AES.encrypt(JSON.stringify(content), app.config.get('cryptokey')).toString()
            },

            /**
             * decrypt the token
             * @memberof app.drivers.security.token
             * @param {string} token - token to decrypt
             * @returns {Object} decrypted content
             */
            decrypt(token){
                let bytes = CryptoJS.AES.decrypt(token.toString(), app.config.get('cryptokey'))
                return JSON.parse(bytes.toString(CryptoJS.enc.Utf8))
            }
        }
    }
}
