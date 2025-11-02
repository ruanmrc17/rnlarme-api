// index.js (Seu novo servidor backend)
require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// --- Configurações ---
app.use(cors()); // Permite que seu app Electron chame esta API
app.use(express.json()); // Permite que o servidor leia JSON

// --- Conexão com o Banco ---
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;
const client = new MongoClient(mongoUri);
let db;

client.connect().then(() => {
    db = client.db("RNLARME_DB");
    console.log("API conectada ao MongoDB (RNLARME_DB)!");
}).catch(err => {
    console.error("Falha ao conectar no MongoDB:", err);
    process.exit(1);
});

// --- Middleware de Autenticação ---
// (Verifica o "Token" em todas as rotas protegidas)
const autenticarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"
    
    if (token == null) return res.sendStatus(401); // Não autorizado

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403); // Token inválido
        req.userId = user.id; // Adiciona o ID do usuário ao 'req'
        next(); // Continua para a rota
    });
};

// --- Funções Auxiliares (Copiadas do seu main.js) ---
async function verificarDisponibilidade(horario, userId, alarmeIdParaIgnorar = null) {
    // (A mesma função que já criamos)
    if (!db || !userId) return false;
    const data = new Date(horario);
    const rangeInicio = new Date(data); rangeInicio.setSeconds(0, 0);
    const rangeFim = new Date(rangeInicio); rangeFim.setMinutes(rangeFim.getMinutes() + 1);
    const query = {
        UserId: new ObjectId(userId), Status: { $in: ["Ativo", 0] },
        Horario: { $gte: rangeInicio, $lt: rangeFim }
    };
    if (alarmeIdParaIgnorar) {
        query._id = { $ne: new ObjectId(alarmeIdParaIgnorar) };
    }
    const count = await db.collection('alarmes').countDocuments(query);
    return (count < 3);
}

function calcularProximaRecorrencia(alarme) {
    // (A mesma função que já criamos)
    let proximoHorario = new Date(alarme.Horario);
    const tipo = alarme.RecorrenciaTipo; 
    const hora = proximoHorario.getHours();
    const minuto = proximoHorario.getMinutes();
    const segundo = proximoHorario.getSeconds();
    if (tipo === "Semanal" || tipo === 0) {
        const diasDaSemana = (alarme.DiasDaSemana || []).map(Number).filter(d => !isNaN(d)).sort((a, b) => a - b);
        if (diasDaSemana.length === 0) return proximoHorario; 
        let diaAtual = proximoHorario.getDay(); 
        let proximoDia = diasDaSemana.find(dia => dia > diaAtual);
        if (proximoDia === undefined) {
            let diasParaSomar = (7 - diaAtual) + diasDaSemana[0];
            proximoHorario.setDate(proximoHorario.getDate() + diasParaSomar);
        } else {
            let diasParaSomar = proximoDia - diaAtual;
            proximoHorario.setDate(proximoHorario.getDate() + diasParaSomar);
        }
    } else if (tipo === "Mensal") {
        const diasDoMes = (alarme.DiasDoMes || []).map(Number).filter(d => !isNaN(d)).sort((a, b) => a - b);
        if (diasDoMes.length === 0) return proximoHorario;
        let diaAtual = proximoHorario.getDate();
        let proximoDia = diasDoMes.find(dia => dia > diaAtual);
        if (proximoDia === undefined) {
            proximoHorario.setMonth(proximoHorario.getMonth() + 1);
            proximoHorario.setDate(diasDoMes[0]);
        } else {
            proximoHorario.setDate(proximoDia);
        }
    }
    proximoHorario.setHours(hora, minuto, segundo, 0);
    return proximoHorario;
}

// --- ROTAS DA API ---

// Rota de Teste
app.get('/', (req, res) => {
  res.send('API do RNLARME está no ar!');
});

// Rota de Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await db.collection('users').findOne({ Username: username.toLowerCase() });
        if (!user) {
            return res.status(404).json({ success: false, message: "Usuário não encontrado" });
        }
        const match = await bcrypt.compare(password, user.PasswordHash);
        if (match) {
            // Cria um Token JWT que expira em 30 dias
            const token = jwt.sign({ id: user._id }, jwtSecret, { expiresIn: '30d' });
            res.json({ success: true, token: token });
        } else {
            res.status(401).json({ success: false, message: "Senha incorreta" });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota de Checagem (só para o serviço de fundo)
// Esta é uma rota especial que o Electron vai chamar
app.post('/checar-alarmes', autenticarToken, async (req, res) => {
    const userId = req.userId;
    const agora = new Date();
    const statusHistorico = ["DisparadoVisto", 1, 2, 3];
    
    try {
        const query = {
            UserId: new ObjectId(userId),
            Horario: { $lte: agora },
            $or: [
                { Status: { $in: ["Ativo", 0] } },
                { IsRecorrente: true, Status: { $in: statusHistorico } }
            ]
        };
        
        const alarmesParaDisparar = await db.collection('alarmes').find(query).toArray();
        let alarmesNotificaveis = [];

        for (const alarme of alarmesParaDisparar) {
            const diffMinutos = (agora.getTime() - new Date(alarme.Horario).getTime()) / (1000 * 60);
            if (diffMinutos < 60) {
                // Prepara para enviar ao Electron
                alarmesNotificaveis.push({ ...alarme, _id: alarme._id.toString() });
            }
            
            if (alarme.IsRecorrente) {
                const proximoHorario = calcularProximaRecorrencia(alarme);
                await db.collection('alarmes').updateOne(
                    { _id: alarme._id }, { $set: { Horario: proximoHorario, Status: "Ativo" } }
                );
            } else {
                await db.collection('alarmes').updateOne(
                    { _id: alarme._id }, { $set: { Status: "DisparadoVisto", DataHistorico: new Date() } }
                );
            }
        }
        // Retorna apenas os alarmes que devem tocar AGORA
        res.json({ success: true, alarmes: alarmesNotificaveis });
        
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// --- ROTAS CRUD (Create, Read, Update, Delete) ---
// Todas as rotas abaixo usam o middleware 'autenticarToken'

app.get('/alarmes/ativos', autenticarToken, async (req, res) => {
    const alarmes = await db.collection('alarmes').find({ 
        UserId: new ObjectId(req.userId), 
        Status: { $in: ["Ativo", 0] }
    }).sort({ Horario: 1 }).toArray();
    res.json(alarmes.map(a => ({ ...a, _id: a._id.toString() })));
});

app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    const statusHistorico = ["DisparadoVisto", 1, 2, 3];
    const alarmes = await db.collection('alarmes').find({ 
        UserId: new ObjectId(req.userId), 
        Status: { $in: statusHistorico }
    }).sort({ Horario: -1 }).toArray();
    res.json(alarmes.map(a => ({ ...a, _id: a._id.toString() })));
});

app.get('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(req.params.id), 
            UserId: new ObjectId(req.userId)
        });
        if (alarme) {
            res.json({ ...alarme, _id: alarme._id.toString() });
        } else {
            res.status(404).json({ message: "Alarme não encontrado" });
        }
    } catch (e) {
        res.status(500).json({ message: e.message });
    }
});

app.post('/alarmes/create', autenticarToken, async (req, res) => {
    const alarme = req.body;
    const novoHorario = new Date(alarme.Horario);
    
    if (novoHorario <= new Date()) {
        return res.status(400).json({ success: false, message: "Data passada." });
    }
    const disponivel = await verificarDisponibilidade(novoHorario, req.userId);
    if (!disponivel) {
        return res.status(400).json({ success: false, message: "Já existem 3 alarmes neste minuto." });
    }
    try {
        const novoAlarme = {
            Horario: novoHorario, Mensagem: alarme.Mensagem, IsRecorrente: alarme.IsRecorrente,
            RecorrenciaTipo: alarme.IsRecorrente ? alarme.RecorrenciaTipo : null,
            DiasDaSemana: alarme.IsRecorrente && alarme.RecorrenciaTipo === 'Semanal' ? alarme.DiasDaSemana : [],
            DiasDoMes: alarme.IsRecorrente && alarme.RecorrenciaTipo === 'Mensal' ? alarme.DiasDoMes : [],
            RecorrenciaInfo: alarme.RecorrenciaInfo || "",
            UserId: new ObjectId(req.userId), Status: "Ativo",
        };
        await db.collection('alarmes').insertOne(novoAlarme);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.put('/alarmes/:id', autenticarToken, async (req, res) => {
    const alarme = req.body;
    const novoHorario = new Date(alarme.Horario);
    
    if (novoHorario <= new Date()) {
        return res.status(400).json({ success: false, message: "Data passada." });
    }
    const disponivel = await verificarDisponibilidade(novoHorario, req.userId, req.params.id);
    if (!disponivel) {
        return res.status(400).json({ success: false, message: "Já existem 3 alarmes neste minuto." });
    }
    try {
        const updateData = {
            Horario: novoHorario, Mensagem: alarme.Mensagem, IsRecorrente: alarme.IsRecorrente,
            RecorrenciaTipo: alarme.IsRecorrente ? alarme.RecorrenciaTipo : null,
            DiasDaSemana: alarme.IsRecorrente && alarme.RecorrenciaTipo === 'Semanal' ? alarme.DiasDaSemana : [],
            DiasDoMes: alarme.IsRecorrente && alarme.RecorrenciaTipo === 'Mensal' ? alarme.DiasDoMes : [],
            RecorrenciaInfo: alarme.RecorrenciaInfo || "", Status: "Ativo"
        };
        const updateOperation = { $set: updateData, $unset: { MensagemOriginal: "" } };
        await db.collection('alarmes').updateOne(
            { _id: new ObjectId(req.params.id), UserId: new ObjectId(req.userId) },
            updateOperation 
        );
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.delete('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        await db.collection('alarmes').deleteOne({ 
            _id: new ObjectId(req.params.id),
            UserId: new ObjectId(req.userId)
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.delete('/alarmes/historico/limpar', autenticarToken, async (req, res) => {
    const statusHistorico = ["DisparadoVisto", 1, 2, 3];
    try {
        await db.collection('alarmes').deleteMany({ 
            UserId: new ObjectId(req.userId),
            Status: { $in: statusHistorico } 
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

app.post('/adiar/:id', autenticarToken, async (req, res) => {
    const { minutos } = req.body;
    const novoHorario = new Date(); novoHorario.setMinutes(novoHorario.getMinutes() + minutos);
    
    const disponivel = await verificarDisponibilidade(novoHorario, req.userId);
    if (!disponivel) {
        return res.status(400).json({ success: false, message: "Já existem 3 alarmes nesse horário." });
    }
    
    try {
        const alarmeObjId = new ObjectId(req.params.id);
        const alarmeOriginal = await db.collection('alarmes').findOne({ _id: alarmeObjId });
        if (!alarmeOriginal) throw new Error("Alarme não encontrado");
        const msgBase = alarmeOriginal.MensagemOriginal || alarmeOriginal.Mensagem;
        
        await db.collection('alarmes').updateOne(
            { _id: alarmeObjId }, 
            { $set: { 
                Horario: novoHorario, Status: "Ativo", IsRecorrente: false, 
                Mensagem: `(Adiado ${minutos}min) ${msgBase}`, MensagemOriginal: msgBase 
            }}
        );
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// --- Iniciar Servidor ---
app.listen(port, () => {
  console.log(`API do RNLARME rodando em http://localhost:${port}`);
});