/**
 * The HTTP Bearer authentication strategy authenticates requests based on
 * a bearer token contained in the `Authorization` header field, `access_token`
 * body parameter, or `access_token` query parameter.
 *
 * For further details on HTTP Bearer authentication, refer to [The OAuth 2.0 Authorization Protocol: Bearer Tokens](http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer)
 *
 * @constructor
 * @param {Object}   req
 * @param {string}   token
 * @param {Function} next
 */
module.exports = function (req, accessToken, next) {
    AccessToken.findOne({ token: accessToken }, function(err, token) {

        if (err) { return next(err); }
        if (!token) { return next(null, false); }

        User.findOne({id: token.userId}, function(err, user) {
            if (err) { return next(err); }
            if (!user) { return next(null, false); }
            return next(null, user, { scope: 'all' });
        });
    });
};
