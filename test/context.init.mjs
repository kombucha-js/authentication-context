
import { filenameOfSettings }             from 'asynchronous-context/settings';
import { dotenvFromSettings }             from 'asynchronous-context/env';

filenameOfSettings( './context.settings.json' );
dotenvFromSettings();
