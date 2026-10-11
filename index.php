<?php
declare(strict_types=1);

$isHttps = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'secure' => $isHttps,
    'samesite' => 'Lax',
]);
session_start();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$loginConfigured = getenv('LOGIN_USERNAME') !== false
    && getenv('LOGIN_PASSWORD_HASH') !== false
    && getenv('LOGIN_USERNAME') !== ''
    && getenv('LOGIN_PASSWORD_HASH') !== '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedToken) || !hash_equals($_SESSION['csrf_token'], $submittedToken)) {
        http_response_code(400);
        $error = 'Your session has expired. Please refresh the page and try again.';
    } elseif (isset($_POST['logout'])) {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    } elseif (!$loginConfigured) {
        $error = 'Login is not configured yet. Set LOGIN_USERNAME and LOGIN_PASSWORD_HASH on the server.';
    } else {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $configuredUsername = getenv('LOGIN_USERNAME');
        $passwordHash = getenv('LOGIN_PASSWORD_HASH');

        if (
            is_string($username)
            && is_string($password)
            && is_string($configuredUsername)
            && is_string($passwordHash)
            && hash_equals($configuredUsername, $username)
            && password_verify($password, $passwordHash)
        ) {
            session_regenerate_id(true);
            $_SESSION['authenticated'] = true;
            $_SESSION['username'] = $configuredUsername;
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        } else {
            $error = 'The username or password you entered is incorrect.';
        }
    }
}

$isAuthenticated = ($_SESSION['authenticated'] ?? false) === true;
$username = htmlspecialchars((string) ($_SESSION['username'] ?? ''), ENT_QUOTES, 'UTF-8');
$csrfToken = htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f4f6fb">
    <title><?= $isAuthenticated ? 'Dashboard' : 'Sign in' ?></title>
    <style>
        :root {
            color-scheme: light;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            color: #182230;
            background: #f4f6fb;
        }

        * { box-sizing: border-box; }

        body {
            min-height: 100vh;
            margin: 0;
            display: grid;
            place-items: center;
            padding: 24px;
            background:
                radial-gradient(ellipse at 15% 10%, rgba(91, 111, 239, .11), transparent 34%),
                radial-gradient(ellipse at 90% 90%, rgba(55, 176, 157, .10), transparent 30%),
                #f4f6fb;
        }

        .card {
            width: min(100%, 420px);
            padding: 42px;
            border: 1px solid rgba(226, 231, 240, .85);
            border-radius: 20px;
            background: rgba(255, 255, 255, .96);
            box-shadow: 0 24px 70px rgba(31, 43, 76, .10);
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 11px;
            margin-bottom: 34px;
            color: #24345d;
            font-size: 15px;
            font-weight: 700;
            letter-spacing: .01em;
        }

        .brand-mark {
            display: grid;
            width: 36px;
            height: 36px;
            place-items: center;
            border-radius: 11px;
            background: #eef0ff;
            color: #5365d9;
        }

        h1 {
            margin: 0 0 9px;
            font-size: clamp(27px, 6vw, 32px);
            letter-spacing: -.04em;
        }

        .subtitle {
            margin: 0 0 30px;
            color: #687386;
            font-size: 15px;
            line-height: 1.6;
        }

        .field { margin-bottom: 19px; }

        label {
            display: block;
            margin-bottom: 8px;
            color: #354052;
            font-size: 13px;
            font-weight: 650;
        }

        input {
            width: 100%;
            height: 48px;
            padding: 0 14px;
            border: 1px solid #dce2ec;
            border-radius: 9px;
            outline: none;
            background: #fff;
            color: #182230;
            font: inherit;
            transition: border-color .15s, box-shadow .15s;
        }

        input::placeholder { color: #a0a9b8; }

        input:focus {
            border-color: #6676e8;
            box-shadow: 0 0 0 3px rgba(102, 118, 232, .15);
        }

        button {
            width: 100%;
            min-height: 48px;
            margin-top: 8px;
            border: 0;
            border-radius: 9px;
            background: #5365d9;
            color: white;
            font: inherit;
            font-size: 15px;
            font-weight: 650;
            cursor: pointer;
            transition: background .15s, transform .15s;
        }

        button:hover { background: #4456ca; }
        button:active { transform: translateY(1px); }
        button:focus-visible { outline: 3px solid #aeb7ff; outline-offset: 3px; }

        .message {
            margin: 0 0 20px;
            padding: 12px 14px;
            border: 1px solid #f2c9c6;
            border-radius: 9px;
            background: #fff6f5;
            color: #9b342d;
            font-size: 13px;
            line-height: 1.5;
        }

        .message.notice {
            border-color: #f1dfb4;
            background: #fffbef;
            color: #765710;
        }

        .signed-in {
            margin: 0 0 26px;
            color: #687386;
            font-size: 15px;
            line-height: 1.6;
        }

        @media (max-width: 480px) {
            .card { padding: 32px 25px; }
        }
    </style>
</head>
<body>
    <main class="card">
        <div class="brand">
            <span class="brand-mark" aria-hidden="true">
                <svg width="19" height="19" viewBox="0 0 24 24" fill="none">
                    <path d="M12 3 4.5 6v5.2c0 4.7 3.2 8.7 7.5 9.8 4.3-1.1 7.5-5.1 7.5-9.8V6L12 3Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
                    <path d="m9 12 2 2 4-4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </span>
            Secure Portal
        </div>

        <?php if ($isAuthenticated): ?>
            <h1>You’re signed in</h1>
            <p class="signed-in">Welcome, <?= $username ?>. Your session is active.</p>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <button type="submit" name="logout" value="1">Sign out</button>
            </form>
        <?php else: ?>
            <h1>Welcome back</h1>
            <p class="subtitle">Sign in to continue to your account.</p>

            <?php if ($error !== ''): ?>
                <p class="message" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
            <?php elseif (!$loginConfigured): ?>
                <p class="message notice" role="status">Server setup is required before you can sign in.</p>
            <?php endif; ?>

            <form method="post" autocomplete="on">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="field">
                    <label for="username">Username</label>
                    <input id="username" name="username" type="text" autocomplete="username" required autofocus>
                </div>
                <div class="field">
                    <label for="password">Password</label>
                    <input id="password" name="password" type="password" autocomplete="current-password" required>
                </div>
                <button type="submit">Sign in</button>
            </form>
        <?php endif; ?>
    </main>
</body>
</html>
