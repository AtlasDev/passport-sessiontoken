/**
 * Module dependencies.
 */
var passport = require('passport');
var util = require('util');


/**
 * @param {Function} verify
 * @param {Object|null} options (optional)
 * @api public
 */
function Strategy(verify, options) {
    if (!options) {
        options = {};
    }
    if (!verify) {
        throw new Error('Strategy requires verify callback.');
    }

    this.field = options.field || 'token';
    this.header = options.header || 'x-token';

    passport.Strategy.call(this);
    this.name = 'sessiontoken';
    this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var key;
    if(req.headers[this.header]) {
        key = req.headers[this.header];
    } else if(req.body[this.field]) {
        key = req.body[this.field];
    } else if(req.query[this.field]) {
        key = req.query[this.field];
    } else {
        var error = new Error('No token found.');
        error.name = 'ENOTFOUND';
        return this.fail(error);
    }

    var _this = this;
    this._verify(apikey, function (err, user, info) {
        if (err) { return _this.error(err); }
        if (!user) { return _this.fail(info); }
        _this.success(user, info);
    });
}


/**
 * Export `Strategy`.
 */
module.exports = Strategy;
