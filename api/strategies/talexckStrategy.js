const OAuth2Strategy = require('passport-oauth2');
const fetch = require('node-fetch');
const socialLogin = require('./socialLogin');

// Map userinfo to the normalized structure our shared socialLogin expects
const getProfileDetails = ({ profile }) => ({
  email: profile.emails?.[0]?.value || profile._json?.email || '',
  id:
    profile.id ||
    profile._json?.id ||
    profile._json?.user_id ||
    profile._json?.sub ||
    profile._json?.email ||
    '',
  avatarUrl: profile.photos?.[0]?.value || 'https://www.talexck.com/favicon.ico',
  username:
    profile.username ||
    profile._json?.username ||
    (profile._json?.email ? profile._json.email.split('@')[0] : 'talexck_user'),
  name: profile.displayName || profile._json?.name || 'TalexCK User',
  emailVerified: true,
});

const talexckLogin = socialLogin('talexck', getProfileDetails);

module.exports = () => {
  const baseUrl = process.env.TALEXCK_BASE_URL || 'https://www.talexck.com';

  const strategy = new OAuth2Strategy(
    {
      authorizationURL: `${baseUrl}/api/sso/oauth2/authorize`,
      tokenURL: `${baseUrl}/api/sso/oauth2/token`,
      clientID: process.env.TALEXCK_CLIENT_ID,
      clientSecret: process.env.TALEXCK_CLIENT_SECRET,
      callbackURL: `${process.env.DOMAIN_SERVER}${process.env.TALEXCK_CALLBACK_URL}`,
      proxy: true,
    },
    talexckLogin,
  );

  // Name the strategy so routes can reference 'talexck'
  strategy.name = 'talexck';

  // Provide a userProfile fetcher so socialLogin receives a proper profile object
  strategy.userProfile = async function userProfile(accessToken, done) {
    try {
      const resp = await fetch(`${baseUrl}/api/sso/oauth2/userinfo`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!resp.ok) {
        return done(new Error(`Failed to fetch userinfo: ${resp.status}`));
      }
      const data = await resp.json();
      const profile = {
        provider: 'talexck',
        id: data.id || data.user_id || data.sub || data.email || null,
        username: data.username || (data.email ? data.email.split('@')[0] : 'talexck_user'),
        displayName: data.name || 'TalexCK User',
        emails: data.email ? [{ value: data.email, verified: true }] : [],
        photos: [{ value: 'https://www.talexck.com/favicon.ico' }],
        _json: data,
      };
      return done(null, profile);
    } catch (err) {
      return done(err);
    }
  };

  return strategy;
};
