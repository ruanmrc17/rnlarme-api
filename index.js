// index.js (Servidor Backend - CORREÇÃO FINAL: IDs são STRINGS)
require('dotenv').config();
const express = require('express');
// IMPORTANTE: Nós NÃO precisamos mais do ObjectId para queries de alarme
const { MongoClient, ObjectId } = require('mongodb'); 
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// --- Configurações ---
app.use(cors()); 
app.use(express.json()); 

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
// (Esta função já estava correta, pois lida apenas com o token)
const autenticarToken = (req, res, next) => {
    console.log("[LOG Autenticar] Recebendo chamada para:", req.path);
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) {
        console.error("[LOG Autenticar] ERRO: Token não encontrado no header.");
        return res.sendStatus(401);
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.error("[LOG Autenticar] ERRO: Falha ao verificar token.", err.message);
            return res.sendStatus(403);
        }
        
        const userIdFromToken = user.userId || user.id;

        if (!userIdFromToken) {
            console.error("[LOG Autenticar] ERRO CRÍTICO: Token não contém 'userId' ou 'id'.");
            return res.sendStatus(403); 
        }

        // req.userId agora é uma STRING (ex: "69035516...") - O que está CORRETO.
        req.userId = userIdFromToken; 
        console.log(`[LOG Autenticar] Token OK. UserId (string) definido como: ${req.userId}`);
        
        next();
    });
};


// --- Rotas de Autenticação ---

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Usuário e senha são obrigatórios.' });
        }

        const user = await db.collection('users').findOne({ Username: username.toLowerCase() });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Usuário não encontrado.' });
        }

        const storedHash = user.PasswordHash; 

        if (!storedHash) {
            console.error(`Erro Crítico: Usuário '${username}' não possui campo 'PasswordHash'.`);
            return res.status(500).json({ success: false, message: 'Erro de configuração da conta.' });
        }

        const match = await bcrypt.compare(password, storedHash); 
        
        if (match) {
            // user._id já é uma STRING, .toString() não faz mal.
            const token = jwt.sign(
                { userId: user._id.toString() }, 
                jwtSecret,
                { expiresIn: '30d' } 
            );
            console.log(`[LOG /login] Usuário '${username}' logado com sucesso.`);
            res.json({ success: true, token: token });
        } else {
            res.status(401).json({ success: false, message: 'Senha incorreta.' });
        }
    } catch (e) {
        console.error("Erro no /login:", e);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

// --- Rotas da API de Alarmes ---

// (A função calcularProximaExecucao não foi alterada)
function calcularProximaExecucao(baseHorario, tipoRecorrencia, diasSemana = [], diasMes = []) {
    let proximaData = new Date(baseHorario.getTime());
    if (tipoRecorrencia === 0) tipoRecorrencia = "Semanal";
    const diasSemanaNum = (diasSemana || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 
    const diasMesNum = (diasMes || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 
    const agora = new Date();
    if (proximaData <= agora) proximaData = agora;
    proximaData.setSeconds(proximaData.getSeconds() + 1);
    if (tipoRecorrencia === 'diariamente') {
        proximaData.setDate(proximaData.getDate() + 1);
    } else if (tipoRecorrencia === 'semanalmente' && diasSemanaNum.length > 0) {
        const hojeNum = proximaData.getDay(); 
        let proximoDiaSemana = diasSemanaNum.find(dia => dia > hojeNum);
        if (proximoDiaSemana !== undefined) {
            proximaData.setDate(proximaData.getDate() + (proximoDiaSemana - hojeNum));
        } else {
            proximaData.setDate(proximaData.getDate() + (7 - hojeNum + diasSemanaNum[0]));
        }
    } else if (tipoRecorrencia === 'mensalmente' && diasMesNum.length > 0) {
        const hojeDia = proximaData.getDate(); 
        let proximoDiaMes = diasMesNum.find(dia => dia > hojeDia);
        if (proximoDiaMes !== undefined) {
             let dataTeste = new Date(proximaData.getTime());
             dataTeste.setDate(proximoDiaMes);
             if (dataTeste.getMonth() === proximaData.getMonth()) {
                 proximaData.setDate(proximoDiaMes);
             } else {
                 proximaData.setMonth(proximaData.getMonth() + 1, diasMesNum[0]);
             }
        } else {
            proximaData.setMonth(proximaData.getMonth() + 1, diasMesNum[0]);
        }
    }
    proximaData.setHours(baseHorario.getHours(), baseHorario.getMinutes(), baseHorario.getSeconds(), 0);
    return proximaData;
}


// GET /alarmes/ativos
app.get('/alarmes/ativos', autenticarToken, async (req, res) => {
    console.log(`[LOG /ativos] Tentando carregar. UserId (string) = ${req.userId}`);
    try {
        const statusAtivos = ["Ativo", 0];

        const alarmes = await db.collection('alarmes')
            // CORREÇÃO: Removido new ObjectId()
            .find({ UserId: req.userId, Status: { $in: statusAtivos } })
            .sort({ Horario: 1 })
            .toArray();
        
        console.log(`[LOG /ativos] Sucesso. Encontrados ${alarmes.length} alarmes ativos.`);
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error(`[LOG /ativos] ERRO no 'catch' da rota:`, e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/historico
app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    console.log(`[LOG /historico] Tentando carregar. UserId (string) = ${req.userId}`);
    try {
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];

        const alarmes = await db.collection('alarmes')
            .find({ 
                // CORREÇÃO: Removido new ObjectId()
                UserId: req.userId, 
                Status: { $in: statusDeHistorico } 
            })
            .sort({ Horario: -1 })
            .limit(100)
            .toArray();
        
        console.log(`[LOG /historico] Sucesso. Encontrados ${alarmes.length} itens no histórico.`);
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error(`[LOG /historico] ERRO no 'catch' da rota:`, e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// DELETE /alarmes/historico/limpar
app.delete('/alarmes/historico/limpar', autenticarToken, async (req, res) => {
    try {
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];

        await db.collection('alarmes').deleteMany({
            // CORREÇÃO: Removido new ObjectId()
            UserId: req.userId,
            Status: { $in: statusDeHistorico }
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/proximos
app.get('/alarmes/proximos', autenticarToken, async (req, res) => {
    try {
        const agora = new Date();
        const statusAtivos = ["Ativo", 0];

        const alarmes = await db.collection('alarmes')
            .find({
                // CORREÇÃO: Removido new ObjectId()
                UserId: req.userId,
                Status: { $in: statusAtivos },
                Horario: { $lte: agora } 
            })
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Tocar"
app.post('/alarmes/tocar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params; // id é uma STRING
    const userId = req.userId; // userId é uma STRING

    try {
        const alarme = await db.collection('alarmes').findOne({
            // CORREÇÃO: Removido new ObjectId() de _id e UserId
            _id: id,
            UserId: userId
        });

        if (!alarme) return res.status(404).json({ message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            const baseTimeParaCalculo = alarme.HorarioBaseRecorrencia || alarme.Horario;
            const proximaData = calcularProximaExecucao(
                new Date(baseTimeParaCalculo), 
                alarme.TipoRecorrencia, 
                alarme.DiasSemana,
                alarme.DiasMes
            );
            
            await db.collection('alarmes').updateOne(
                { _id: id }, // CORREÇÃO: Removido new ObjectId()
                { $set: { Horario: proximaData, Status: "Ativo", Mensagem: alarme.MensagemOriginal || alarme.Mensagem },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: id }, // CORREÇÃO: Removido new ObjectId()
                { $set: { Status: "DisparadoVisto" }, 
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        }
        res.json({ success: true, alarmeDisparado: alarme });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Visto"
app.post('/alarmes/visto/:id', autenticarToken, async (req, res) => {
    const { id } = req.params; // id é uma STRING
    const userId = req.userId; // userId é uma STRING
    
    try {
        const alarme = await db.collection('alarmes').findOne({
            // CORREÇÃO: Removido new ObjectId()
            _id: id,
            UserId: userId
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            const baseTimeParaCalculo = alarme.HorarioBaseRecorrencia || alarme.Horario;
            const proximaData = calcularProximaExecucao(
                new Date(baseTimeParaCalculo), 
                alarme.TipoRecorrencia, 
                alarme.DiasSemana,
                alarme.DiasMes
            );
            
            await db.collection('alarmes').updateOne(
                { _id: id }, // CORREÇÃO: Removido new ObjectId()
                { $set: { Horario: proximaData, Status: "Ativo", Mensagem: alarme.MensagemOriginal || alarme.Mensagem },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: id }, // CORREÇÃO: Removido new ObjectId()
                { $set: { Status: "DisparadoVisto" },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Adiar"
app.post('/alarmes/adiar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params; // id é uma STRING
    const userId = req.userId; // userId é uma STRING
    const { minutos } = req.body;

    try {
        const alarme = await db.collection('alarmes').findOne({
            // CORREÇÃO: Removido new ObjectId()
            _id: id,
            UserId: userId
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        const agora = new Date();
        const novoHorario = new Date(agora.getTime() + parseInt(minutos) * 60000);
        const msgBase = alarme.MensagemOriginal || alarme.Mensagem;
        const horarioBase = alarme.HorarioBaseRecorrencia || alarme.Horario;

        await db.collection('alarmes').updateOne(
            { _id: id }, // CORREÇÃO: Removido new ObjectId()
            { $set: { 
                Horario: novoHorario, 
                Status: "Ativo", 
                Mensagem: `(Adiado ${minutos}min) ${msgBase}`, 
                MensagemOriginal: msgBase,
                HorarioBaseRecorrencia: new Date(horarioBase) 
            }}
        );
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});


// Rota de Limpeza (Cron Job) - (Sem alterações, não usa ID)
app.get('/tasks/cleanup-old-history', async (req, res) => {
    const cronSecret = req.headers['x-cron-secret'];
    if (cronSecret !== process.env.CRON_SECRET) return res.sendStatus(401); 
    try {
        const dataLimite = new Date();
        dataLimite.setDate(dataLimite.getDate() - 30);
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3]; 
        const resultado = await db.collection('alarmes').deleteMany({
            Status: { $in: statusDeHistorico }, 
            Horario: { $lt: dataLimite } 
        });
        console.log(`[LIMPEZA CRON] ${resultado.deletedCount} alarmes antigos foram apagados.`);
        res.status(200).json({ message: "Limpeza de alarmes antigos concluída.", deletedCount: resultado.deletedCount });
    } catch (e) {
        console.error("[LIMPEZA CRON] Erro:", e);
        res.status(500).json({ message: "Erro interno na limpeza." });
    }
});

// --- Rotas CRUD Padrão ---

// GET /alarmes/:id
app.get('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const alarme = await db.collection('alarmes').findOne({
            // CORREÇÃO: Removido new ObjectId()
            _id: req.params.id,
            UserId: req.userId
        });
        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        res.json({ success: true, alarme });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// POST /alarmes (Criar)
app.post('/alarmes', autenticarToken, async (req, res) => {
    try {
        const alarme = req.body;
        
        // CORREÇÃO: Removido new ObjectId()
        alarme.UserId = req.userId;
        alarme.Horario = new Date(alarme.Horario);
        alarme.Status = "Ativo"; 

        if(alarme.IsRecorrente) {
            const agora = new Date();
            alarme.Horario = calcularProximaExecucao(
                agora, 
                alarme.TipoRecorrencia, 
                alarme.DiasSemana, 
                alarme.DiasMes
            );
            const horarioBase = new Date(req.body.Horario); 
            alarme.Horario.setHours(horarioBase.getHours(), horarioBase.getMinutes(), 0, 0);
        }

        // *** IMPORTANTE ***
        // Ao criar, o MongoDB vai gerar um _id automático (que será um ObjectId REAL)
        // Mas o seu código antigo parecia não ter um _id, ou o _id era uma string.
        // Se a *criação* de alarmes falhar, teremos que ajustar aqui.
        // Mas a LEITURA agora está correTA.
        // Vamos deixar o MongoDB criar o _id.
        
        const result = await db.collection('alarmes').insertOne(alarme);
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// PUT /alarmes/:id (Atualizar)
app.put('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params; // id é uma STRING
        const alarmeUpdate = req.body;

        delete alarmeUpdate._id; 
        
        alarmeUpdate.Horario = new Date(alarmeUpdate.Horario);
        alarmeUpdate.Status = "Ativo"; 
        
        delete alarmeUpdate.MensagemOriginal;
        delete alarmeUpdate.HorarioBaseRecorrencia;

        if(alarmeUpdate.IsRecorrente) {
            const agora = new Date();
            alarmeUpdate.Horario = calcularProximaExecucao(
                agora, 
                alarmeUpdate.TipoRecorrencia, 
                alarmeUpdate.DiasSemana, 
                alarmeUpdate.DiasMes
            );
            const horarioBase = new Date(req.body.Horario);
            alarmeUpdate.Horario.setHours(horarioBase.getHours(), horarioBase.getMinutes(), 0, 0);
        }

        const result = await db.collection('alarmes').updateOne(
            // CORREÇÃO: Removido new ObjectId()
            { _id: id, UserId: req.userId },
            { $set: alarmeUpdate,
              $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// DELETE /alarmes/:id
app.delete('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params; // id é uma STRING
        const result = await db.collection('alarmes').deleteOne({
            // CORREÇÃO: Removido new ObjectId()
            _id: id,
            UserId: req.userId
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        res.status(204).send(); // 204 No Content
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// --- Iniciar Servidor ---
app.listen(port, () => {
    console.log(`API RNLARME rodando na porta ${port}`);
});
