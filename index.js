// index.js (Servidor Backend COM LOGS DE DEBUG)
require('dotenv').config();
const express = require('express');
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
const autenticarToken = (req, res, next) => {
    // LOG (1): Verificando o header
    console.log("[LOG Autenticar] Recebendo chamada para:", req.path);
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) {
        console.error("[LOG Autenticar] ERRO: Token não encontrado no header.");
        return res.sendStatus(401); // Não autorizado
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.error("[LOG Autenticar] ERRO: Falha ao verificar token (inválido ou expirado).", err.message);
            return res.sendStatus(403); // Token inválido
        }
        
        // LOG (2): Verificando o payload do token
        const userIdFromToken = user.userId || user.id;

        if (!userIdFromToken) {
            console.error("[LOG Autenticar] ERRO CRÍTICO: Token verificado, mas não contém 'userId' ou 'id'. Payload:", user);
            return res.sendStatus(403); 
        }

        // LOG (3): Sucesso!
        console.log(`[LOG Autenticar] Token OK. UserId definido como: ${userIdFromToken}`);
        req.userId = userIdFromToken; 
        
        next(); // Continua para a rota
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
            // Cria token com 'userId'
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
    
    if (tipoRecorrencia === 0) {
        tipoRecorrencia = "Semanal";
    }

    const diasSemanaNum = (diasSemana || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 
    const diasMesNum = (diasMes || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 

    const agora = new Date();
    if (proximaData <= agora) {
        proximaData = agora;
    }
    
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
    // === INÍCIO DO LOG DE DEBUG ===
    console.log(`[LOG /ativos] Tentando carregar alarmes ativos.`);
    console.log(`[LOG /ativos] req.userId recebido do token: ${req.userId}`);
    if (!req.userId) {
        console.error("[LOG /ativos] ERRO CRÍTICO: req.userId está NULO ou INDEFINIDO. O middleware falhou em definir.");
        // A autenticação já deve ter parado isso, mas é uma segurança extra
        return res.status(500).json({ success: false, message: "UserID nulo após autenticação." });
    }
    // === FIM DO LOG DE DEBUG ===

    try {
        const statusAtivos = ["Ativo", 0];

        const alarmes = await db.collection('alarmes')
            .find({ UserId: new ObjectId(req.userId), Status: { $in: statusAtivos } })
            .sort({ Horario: 1 })
            .toArray();
        
        console.log(`[LOG /ativos] Sucesso. Encontrados ${alarmes.length} alarmes ativos para ${req.userId}.`);
        res.json({ success: true, alarmes });
    } catch (e) {
        // Log de Erro Detalhado
        console.error(`[LOG /ativos] ERRO no 'catch' da rota /alarmes/ativos para UserId: ${req.userId}`);
        console.error(e); // Loga o objeto de erro completo
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/historico
app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    // === INÍCIO DO LOG DE DEBUG ===
    console.log(`[LOG /historico] Tentando carregar histórico.`);
    console.log(`[LOG /historico] req.userId recebido do token: ${req.userId}`);
    if (!req.userId) {
        console.error("[LOG /historico] ERRO CRÍTICO: req.userId está NULO ou INDEFINIDO. O middleware falhou em definir.");
        return res.status(500).json({ success: false, message: "UserID nulo após autenticação." });
    }
    // === FIM DO LOG DE DEBUG ===

    try {
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];

        const alarmes = await db.collection('alarmes')
            .find({ 
                UserId: new ObjectId(req.userId), 
                Status: { $in: statusDeHistorico } 
            })
            .sort({ Horario: -1 })
            .limit(100)
            .toArray();
        
        console.log(`[LOG /historico] Sucesso. Encontrados ${alarmes.length} itens no histórico para ${req.userId}.`);
        res.json({ success: true, alarmes });
    } catch (e) {
        // Log de Erro Detalhado
        console.error(`[LOG /historico] ERRO no 'catch' da rota /alarmes/historico para UserId: ${req.userId}`);
        console.error(e); // Loga o objeto de erro completo
        res.status(500).json({ success: false, message: e.message });
    }
});

// DELETE /alarmes/historico/limpar
app.delete('/alarmes/historico/limpar', autenticarToken, async (req, res) => {
    try {
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];

        await db.collection('alarmes').deleteMany({
            UserId: new ObjectId(req.userId),
            Status: { $in: statusDeHistorico }
        });
        res.json({ success: true });
    } catch (e) {
        console.error(`[LOG /historico/limpar] ERRO:`, e.message);
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
                UserId: new ObjectId(req.userId),
                Status: { $in: statusAtivos },
                Horario: { $lte: agora } 
            })
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error(`[LOG /proximos] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Tocar"
app.post('/alarmes/tocar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            UserId: new ObjectId(userId)
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
                { _id: new ObjectId(id) },
                { 
                    $set: { 
                        Horario: proximaData, 
                        Status: "Ativo", 
                        Mensagem: alarme.MensagemOriginal || alarme.Mensagem 
                    },
                    $unset: {
                        MensagemOriginal: "", 
                        HorarioBaseRecorrencia: "" 
                    }
                }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) },
                { 
                    $set: { Status: "DisparadoVisto" }, 
                    $unset: {
                        MensagemOriginal: "",
                        HorarioBaseRecorrencia: ""
                    }
                }
            );
        }
        res.json({ success: true, alarmeDisparado: alarme });
    } catch (e) {
        console.error(`[LOG /tocar] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Visto"
app.post('/alarmes/visto/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;
    
    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            UserId: new ObjectId(userId)
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
                { _id: new ObjectId(id) },
                { 
                    $set: { 
                        Horario: proximaData, 
                        Status: "Ativo", 
                        Mensagem: alarme.MensagemOriginal || alarme.Mensagem
                    },
                    $unset: {
                        MensagemOriginal: "",
                        HorarioBaseRecorrencia: ""
                    }
                }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) },
                { 
                    $set: { Status: "DisparadoVisto" }, 
                    $unset: {
                        MensagemOriginal: "",
                        HorarioBaseRecorrencia: ""
                    }
                }
            );
        }
        res.json({ success: true });
    } catch (e) {
        console.error(`[LOG /visto] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Adiar"
app.post('/alarmes/adiar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;
    const { minutos } = req.body;

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            UserId: new ObjectId(userId)
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        const agora = new Date();
        const novoHorario = new Date(agora.getTime() + parseInt(minutos) * 60000);
        
        const msgBase = alarme.MensagemOriginal || alarme.Mensagem;
        const horarioBase = alarme.HorarioBaseRecorrencia || alarme.Horario;

        await db.collection('alarmes').updateOne(
            { _id: new ObjectId(id) },
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
        console.error(`[LOG /adiar] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});


// Rota de Limpeza (Cron Job)
app.get('/tasks/cleanup-old-history', async (req, res) => {
    
    const cronSecret = req.headers['x-cron-secret'];
    if (cronSecret !== process.env.CRON_SECRET) {
        return res.sendStatus(401); 
    }
    
    try {
        const dataLimite = new Date();
        dataLimite.setDate(dataLimite.getDate() - 30);
        
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3]; 

        const resultado = await db.collection('alarmes').deleteMany({
            Status: { $in: statusDeHistorico }, 
            Horario: { $lt: dataLimite } 
        });

        console.log(`[LIMPEZA CRON] ${resultado.deletedCount} alarmes antigos foram apagados.`);
        
        res.status(200).json({
            message: "Limpeza de alarmes antigos concluída.",
            deletedCount: resultado.deletedCount
        });

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
            _id: new ObjectId(req.params.id),
            UserId: new ObjectId(req.userId)
        });
        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        res.json({ success: true, alarme });
    } catch (e) {
        console.error(`[LOG /alarmes/:id] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// POST /alarmes (Criar)
app.post('/alarmes', autenticarToken, async (req, res) => {
    try {
        const alarme = req.body;
        
        alarme.UserId = new ObjectId(req.userId);
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

        const result = await db.collection('alarmes').insertOne(alarme);
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (e) {
        console.error(`[LOG /alarmes (POST)] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// PUT /alarmes/:id (Atualizar)
app.put('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params;
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
            { _id: new ObjectId(id), UserId: new ObjectId(req.userId) },
            { 
                $set: alarmeUpdate,
                $unset: { 
                    MensagemOriginal: "",
                    HorarioBaseRecorrencia: ""
                }
            }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        res.json({ success: true });
    } catch (e) {
        console.error(`[LOG /alarmes/:id (PUT)] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// DELETE /alarmes/:id
app.delete('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.collection('alarmes').deleteOne({
            _id: new ObjectId(id),
            UserId: new ObjectId(req.userId)
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        res.status(204).send(); // 204 No Content
    } catch (e) {
        console.error(`[LOG /alarmes/:id (DELETE)] ERRO:`, e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// --- Iniciar Servidor ---
app.listen(port, () => {
    console.log(`API RNLARME rodando na porta ${port}`);
});
