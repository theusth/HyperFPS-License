require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const requiredVariables = [
  'SUPABASE_URL',
  'SUPABASE_SECRET_KEY',
  'JWT_SECRET',
  'ADMIN_TOKEN'
];

for (const key of requiredVariables) {
  if (!process.env[key]) {
    throw new Error(`Variável ausente: ${key}`);
  }
}

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.set('trust proxy', 1);

app.use(
  cors({
    origin:
      !process.env.CORS_ORIGIN ||
      process.env.CORS_ORIGIN === '*'
        ? true
        : process.env.CORS_ORIGIN,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-admin-token'
    ]
  })
);

app.options('*', cors());

app.use(express.json({ limit: '32kb' }));

app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 150,
    standardHeaders: true,
    legacyHeaders: false
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

const sha256 = value => {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex');
};

const normalizeUser = value => {
  return String(value || '')
    .trim()
    .toLowerCase();
};

const generateKey = () => {
  const parts = Array.from(
    { length: 3 },
    () =>
      crypto
        .randomBytes(3)
        .toString('hex')
        .toUpperCase()
  );

  return `HYPER-${parts.join('-')}`;
};

const clientIp = req => {
  return String(
    req.headers['x-forwarded-for'] ||
    req.headers['x-real-ip'] ||
    req.ip ||
    ''
  )
    .split(',')[0]
    .trim()
    .slice(0, 100);
};

async function logAttempt(
  req,
  username,
  hwid,
  success
) {
  try {
    const { error } = await supabase
      .from('login_logs')
      .insert({
        username: normalizeUser(username),
        ip: clientIp(req),
        hwid: hwid ? sha256(hwid) : null,
        success: Boolean(success)
      });

    if (error) {
      console.error(
        'Falha ao salvar log:',
        error.message
      );
    }
  } catch (error) {
    console.error(
      'Erro inesperado ao salvar log:',
      error.message
    );
  }
}

function adminOnly(req, res, next) {
  const received = String(
    req.headers['x-admin-token'] || ''
  );

  const expected = String(
    process.env.ADMIN_TOKEN || ''
  );

  if (
    !received ||
    !expected ||
    received.length !== expected.length
  ) {
    return res.status(401).json({
      success: false,
      message: 'Token administrativo inválido.'
    });
  }

  const valid = crypto.timingSafeEqual(
    Buffer.from(received, 'utf8'),
    Buffer.from(expected, 'utf8')
  );

  if (!valid) {
    return res.status(401).json({
      success: false,
      message: 'Token administrativo inválido.'
    });
  }

  next();
}

/* =========================
   STATUS DA API
========================= */

app.get('/api/health', (_req, res) => {
  return res.status(200).json({
    online: true,
    service: 'HyperFPS API',
    version: '1.0.0',
    environment:
      process.env.VERCEL === '1'
        ? 'vercel'
        : 'local'
  });
});

/* =========================
   LOGIN
========================= */

app.post('/api/login', async (req, res) => {
  try {
    const {
      username,
      password,
      licenseKey,
      hwid
    } = req.body || {};

    if (
      !username ||
      !password ||
      !licenseKey ||
      !hwid
    ) {
      return res.status(400).json({
        success: false,
        message:
          'Informe usuário, senha, key e HWID.'
      });
    }

    const normalizedUsername =
      normalizeUser(username);

    const {
      data: user,
      error: userError
    } = await supabase
      .from('users')
      .select('*')
      .eq('username', normalizedUsername)
      .maybeSingle();

    if (userError) {
      throw userError;
    }

    const passwordValid =
      Boolean(user?.password_hash) &&
      await bcrypt.compare(
        String(password),
        user.password_hash
      );

    const normalizedKey = String(licenseKey)
      .trim()
      .toUpperCase();

    const keyValid =
      Boolean(user?.key_hash) &&
      sha256(normalizedKey) === user.key_hash;

    if (
      !user ||
      !passwordValid ||
      !keyValid
    ) {
      await logAttempt(
        req,
        normalizedUsername,
        hwid,
        false
      );

      return res.status(401).json({
        success: false,
        message:
          'Usuário, senha ou key inválidos.'
      });
    }

    if (user.status !== 'active') {
      await logAttempt(
        req,
        normalizedUsername,
        hwid,
        false
      );

      return res.status(403).json({
        success: false,
        message:
          user.blocked_reason ||
          'Licença bloqueada.'
      });
    }

    if (
      user.expires_at &&
      new Date(user.expires_at).getTime() <=
        Date.now()
    ) {
      await logAttempt(
        req,
        normalizedUsername,
        hwid,
        false
      );

      return res.status(403).json({
        success: false,
        message: 'Licença expirada.'
      });
    }

    const incomingHwid = sha256(hwid);
    const now = new Date().toISOString();

    if (!user.hwid_hash) {
      const {
        error: bindError
      } = await supabase
        .from('users')
        .update({
          hwid_hash: incomingHwid,
          last_login: now
        })
        .eq('id', user.id);

      if (bindError) {
        throw bindError;
      }
    } else if (
      user.hwid_hash !== incomingHwid
    ) {
      const {
        error: failedHwidError
      } = await supabase
        .from('users')
        .update({
          failed_hwid_attempts:
            Number(
              user.failed_hwid_attempts || 0
            ) + 1
        })
        .eq('id', user.id);

      if (failedHwidError) {
        console.error(
          'Erro ao atualizar tentativas de HWID:',
          failedHwidError.message
        );
      }

      await logAttempt(
        req,
        normalizedUsername,
        hwid,
        false
      );

      return res.status(403).json({
        success: false,
        message:
          'Esta key já está vinculada a outro computador.'
      });
    } else {
      const {
        error: lastLoginError
      } = await supabase
        .from('users')
        .update({
          last_login: now
        })
        .eq('id', user.id);

      if (lastLoginError) {
        throw lastLoginError;
      }
    }

    await logAttempt(
      req,
      normalizedUsername,
      hwid,
      true
    );

    const token = jwt.sign(
      {
        sub: user.id,
        username: user.username,
        plan: user.plan
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '12h'
      }
    );

    return res.status(200).json({
      success: true,
      token,
      user: {
        username: user.username,
        plan: user.plan,
        expiresAt: user.expires_at
      }
    });
  } catch (error) {
    console.error(
      'Erro no login:',
      error
    );

    return res.status(500).json({
      success: false,
      message:
        'Erro interno ao validar a licença.'
    });
  }
});

/* =========================
   ATUALIZAÇÕES
========================= */

app.get('/api/update', async (_req, res) => {
  try {
    const {
      data,
      error
    } = await supabase
      .from('updates')
      .select('*')
      .order('created_at', {
        ascending: false
      })
      .limit(1)
      .maybeSingle();

    if (error) {
      throw error;
    }

    return res.status(200).json({
      success: true,
      update: data || null
    });
  } catch (error) {
    console.error(
      'Erro ao consultar atualização:',
      error
    );

    return res.status(500).json({
      success: false,
      message:
        'Erro ao consultar atualização.'
    });
  }
});

/* =========================
   LISTAR USUÁRIOS
========================= */

app.get(
  '/api/admin/users',
  adminOnly,
  async (_req, res) => {
    try {
      const {
        data,
        error
      } = await supabase
        .from('users')
        .select(
          [
            'id',
            'username',
            'email',
            'plan',
            'expires_at',
            'status',
            'failed_hwid_attempts',
            'blocked_reason',
            'created_at',
            'last_login',
            'hwid_hash'
          ].join(',')
        )
        .order('created_at', {
          ascending: false
        });

      if (error) {
        throw error;
      }

      return res.status(200).json({
        success: true,
        users: data || []
      });
    } catch (error) {
      console.error(
        'Erro ao listar usuários:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao listar usuários.'
      });
    }
  }
);

/* =========================
   CRIAR USUÁRIO
========================= */

app.post(
  '/api/admin/users',
  adminOnly,
  async (req, res) => {
    try {
      const {
        username,
        password,
        email = null,
        plan = 'Premium',
        days = null
      } = req.body || {};

      if (
        !username ||
        !password ||
        String(password).length < 8
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Informe usuário e senha com pelo menos 8 caracteres.'
        });
      }

      const normalizedUsername =
        normalizeUser(username);

      if (
        normalizedUsername.length < 3 ||
        normalizedUsername.length > 50
      ) {
        return res.status(400).json({
          success: false,
          message:
            'O usuário deve ter entre 3 e 50 caracteres.'
        });
      }

      const numericDays = Number(days);

      const expiresAt =
        Number.isFinite(numericDays) &&
        numericDays > 0
          ? new Date(
              Date.now() +
              numericDays * 86400000
            ).toISOString()
          : null;

      const licenseKey = generateKey();

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      const {
        data,
        error
      } = await supabase
        .from('users')
        .insert({
          username: normalizedUsername,
          password_hash: passwordHash,
          key_hash: sha256(licenseKey),
          email:
            email
              ? String(email)
                .trim()
                .toLowerCase()
              : null,
          plan: String(plan || 'Premium')
            .trim()
            .slice(0, 50),
          expires_at: expiresAt,
          status: 'active',
          failed_hwid_attempts: 0
        })
        .select(
          'id,username,email,plan,expires_at,status,created_at'
        )
        .single();

      if (error) {
        if (error.code === '23505') {
          return res.status(409).json({
            success: false,
            message: 'Usuário já existe.'
          });
        }

        throw error;
      }

      return res.status(201).json({
        success: true,
        user: data,
        licenseKey
      });
    } catch (error) {
      console.error(
        'Erro ao criar usuário:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao criar usuário.'
      });
    }
  }
);

/* =========================
   RESETAR HWID
========================= */

app.post(
  '/api/admin/users/:id/reset-hwid',
  adminOnly,
  async (req, res) => {
    try {
      const {
        data,
        error
      } = await supabase
        .from('users')
        .update({
          hwid_hash: null,
          failed_hwid_attempts: 0
        })
        .eq('id', req.params.id)
        .select('id,username')
        .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message:
            'Usuário não encontrado.'
        });
      }

      return res.status(200).json({
        success: true,
        message: 'HWID resetado.',
        user: data
      });
    } catch (error) {
      console.error(
        'Erro ao resetar HWID:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao resetar HWID.'
      });
    }
  }
);

/* =========================
   BLOQUEAR/DESBLOQUEAR
========================= */

app.patch(
  '/api/admin/users/:id/status',
  adminOnly,
  async (req, res) => {
    try {
      const status =
        req.body?.status === 'blocked'
          ? 'blocked'
          : 'active';

      const blockedReason =
        status === 'blocked'
          ? String(
              req.body?.reason ||
              'Bloqueado pelo administrador'
            ).slice(0, 300)
          : null;

      const {
        data,
        error
      } = await supabase
        .from('users')
        .update({
          status,
          blocked_reason: blockedReason
        })
        .eq('id', req.params.id)
        .select(
          'id,username,status,blocked_reason'
        )
        .maybeSingle();

      if (error) {
        throw error;
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message:
            'Usuário não encontrado.'
        });
      }

      return res.status(200).json({
        success: true,
        user: data
      });
    } catch (error) {
      console.error(
        'Erro ao alterar status:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao alterar status.'
      });
    }
  }
);


/* =========================
   EXCLUIR USUÁRIO / KEY
========================= */

app.delete(
  '/api/admin/users/:id',
  adminOnly,
  async (req, res) => {
    try {
      const userId = String(req.params.id || '').trim();

      if (!userId) {
        return res.status(400).json({
          success: false,
          message: 'ID do usuário não informado.'
        });
      }

      const {
        data: existingUser,
        error: findError
      } = await supabase
        .from('users')
        .select('id,username')
        .eq('id', userId)
        .maybeSingle();

      if (findError) {
        throw findError;
      }

      if (!existingUser) {
        return res.status(404).json({
          success: false,
          message: 'Usuário não encontrado.'
        });
      }

      const { error: deleteError } = await supabase
        .from('users')
        .delete()
        .eq('id', userId);

      if (deleteError) {
        throw deleteError;
      }

      return res.status(200).json({
        success: true,
        message: 'Usuário e key excluídos.',
        user: existingUser
      });
    } catch (error) {
      console.error(
        'Erro ao excluir usuário:',
        error
      );

      return res.status(500).json({
        success: false,
        message: 'Erro ao excluir usuário.'
      });
    }
  }
);

/* =========================
   LOGS
========================= */

app.get(
  '/api/admin/logs',
  adminOnly,
  async (_req, res) => {
    try {
      const {
        data,
        error
      } = await supabase
        .from('login_logs')
        .select('*')
        .order('created_at', {
          ascending: false
        })
        .limit(200);

      if (error) {
        throw error;
      }

      return res.status(200).json({
        success: true,
        logs: data || []
      });
    } catch (error) {
      console.error(
        'Erro ao listar logs:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao listar logs.'
      });
    }
  }
);

/* =========================
   CRIAR ATUALIZAÇÃO
========================= */

app.post(
  '/api/admin/update',
  adminOnly,
  async (req, res) => {
    try {
      const {
        version,
        downloadUrl = null,
        changelog = '',
        forceUpdate = false
      } = req.body || {};

      if (!version) {
        return res.status(400).json({
          success: false,
          message: 'Informe a versão.'
        });
      }

      const {
        data,
        error
      } = await supabase
        .from('updates')
        .insert({
          version: String(version)
            .trim()
            .slice(0, 50),
          download_url:
            downloadUrl
              ? String(downloadUrl)
                .trim()
                .slice(0, 1000)
              : null,
          changelog: String(changelog)
            .slice(0, 5000),
          force_update:
            Boolean(forceUpdate)
        })
        .select('*')
        .single();

      if (error) {
        throw error;
      }

      return res.status(201).json({
        success: true,
        update: data
      });
    } catch (error) {
      console.error(
        'Erro ao criar atualização:',
        error
      );

      return res.status(500).json({
        success: false,
        message:
          'Erro ao criar atualização.'
      });
    }
  }
);

/* =========================
   ROTAS NÃO ENCONTRADAS
========================= */

app.use('/api', (_req, res) => {
  return res.status(404).json({
    success: false,
    message:
      'Rota da API não encontrada.'
  });
});

/*
  Compatível com Express 5.
  Não use app.get('*'), pois pode gerar
  o erro "Missing parameter name".
*/
app.get('/{*splat}', (_req, res) => {
  return res.sendFile(
    path.join(
      __dirname,
      'public',
      'index.html'
    )
  );
});

/* =========================
   LOCAL + VERCEL
========================= */

const port = Number(
  process.env.PORT || 3000
);

/*
  Na Vercel, o Express é exportado.
  No computador, npm start inicia
  normalmente na porta 3000.
*/
if (process.env.VERCEL !== '1') {
  app.listen(
    port,
    '0.0.0.0',
    () => {
      console.log(
        `HyperFPS API online na porta ${port}`
      );
    }
  );
}

module.exports = app;
