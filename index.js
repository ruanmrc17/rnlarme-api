// index.js (Servidor Backend COMPLETO E DEFINITIVO)
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

// ==================================================================
// *** CORREÇÃO CRÍTICA DE AUTENTICAÇÃO ***
// ==================================================================
// --- Middleware de Autenticação ---
const autenticarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) return res.sendStatus(401); // Não autorizado

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            console.warn("Falha ao verificar token (inválido ou expirado):", err.message);
            return res.sendStatus(403); // Token inválido
        }
        
        // *** INÍCIO DA CORREÇÃO DE COMPATIBILIDADE DE TOKEN ***
        // Procura o ID no payload 'user.userId' (para tokens novos)
        // OU no 'user.id' (para tokens antigos que ainda podem existir)
        const userIdFromToken = user.userId || user.id;

        if (!userIdFromToken) {
            // Se o token não tem nem .id nem .userId, é inválido
            console.error("Token inválido, sem 'userId' ou 'id' no payload.");
            return res.sendStatus(403); 
        }

        // Adiciona o ID (encontrado) ao 'req'
        req.userId = userIdFromToken; 
        // *** FIM DA CORREÇÃO ***
        
        next(); // Continua para a rota
    });
};
// ==================================================================


// --- Rotas de Autenticação ---

// Rota de Login (Corrigida para PasswordHash e novo payload de token)
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

        // CORREÇÃO: Usando o campo 'PasswordHash' do seu DB
        const storedHash = user.PasswordHash; 

        if (!storedHash) {
            console.error(`Erro Crítico: Usuário '${username}' não possui campo 'PasswordHash'.`);
            return res.status(500).json({ success: false, message: 'Erro de configuração da conta.' });
        }

        const match = await bcrypt.compare(password, storedHash); 
        
        if (match) {
            // CORREÇÃO: O payload é 'userId' (minúsculo) para novos tokens
            const token = jwt.sign(
                { userId: user._id.toString() }, 
                jwtSecret,
                { expiresIn: '30d' } 
            );
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

// Função Auxiliar de Recorrência (Corrigida para tipo '0')
function calcularProximaExecucao(baseHorario, tipoRecorrencia, diasSemana = [], diasMes = []) {
    let proximaData = new Date(baseHorario.getTime());
    
    // CORREÇÃO: O seu "arquivo antigo" mostra que tipo 0 = Semanal
    if (tipoRecorrencia === 0) {
        tipoRecorrencia = "Semanal";
    }

    const diasSemanaNum = (diasSemana || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 
    const diasMesNum = (diasMes || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 

    const agora = new Date();
    // Garante que o cálculo comece a partir de 'agora' se a base for no passado
    if (proximaData <= agora) {
        proximaData = agora;
    }
    
    // Adiciona 1 segundo para garantir que não pegue a data/hora atual exata
    proximaData.setSeconds(proximaData.getSeconds() + 1);

    if (tipoRecorrencia === 'diariamente') {
        proximaData.setDate(proximaData.getDate() + 1);
        
    } else if (tipoRecorrencia === 'semanalmente' && diasSemanaNum.length > 0) {
        const hojeNum = proximaData.getDay(); // Dia da semana atual (0-6)
        
        let proximoDiaSemana = diasSemanaNum.find(dia => dia > hojeNum);
        
        if (proximoDiaSemana !== undefined) {
            // Se achou, avança os dias
            proximaData.setDate(proximaData.getDate() + (proximoDiaSemana - hojeNum));
        } else {
            // Se não achou (ex: hoje é sexta, próximo é seg), pega o primeiro da próx. semana
            proximaData.setDate(proximaData.getDate() + (7 - hojeNum + diasSemanaNum[0]));
        }

    } else if (tipoRecorrencia === 'mensalmente' && diasMesNum.length > 0) {
        const hojeDia = proximaData.getDate(); // Dia do mês atual (1-31)

        let proximoDiaMes = diasMesNum.find(dia => dia > hojeDia);
        
        if (proximoDiaMes !== undefined) {
             let dataTeste = new Date(proximaData.getTime());
             dataTeste.setDate(proximoDiaMes);
             
             // Se o dia (ex: 31) não existir no mês atual (ex: Fev), o JS pula pro próx. mês
             if (dataTeste.getMonth() === proximaData.getMonth()) {
                 proximaData.setDate(proximoDiaMes);
             } else {
                 // Se pulou o mês, pulamos para o próximo mês válido
                 proximaData.setMonth(proximaData.getMonth() + 1, diasMesNum[0]);
             }
            
        } else {
            // Não há mais dias válidos este mês, vai pro próximo
            proximaData.setMonth(proximaData.getMonth() + 1, diasMesNum[0]);
        }
    }
    
    // Define o horário base (ex: 8:55:00)
    proximaData.setHours(baseHorario.getHours(), baseHorario.getMinutes(), baseHorario.getSeconds(), 0);
    
    return proximaData;
}


// GET /alarmes/ativos
app.get('/alarmes/ativos', autenticarToken, async (req, res) => {
    try {
        // CORREÇÃO: Status "Ativo" (string) ou 0 (número)
        const statusAtivos = ["Ativo", 0];

        const alarmes = await db.collection('alarmes')
            // CORREÇÃO: 'UserId' (maiúsculo)
            .find({ UserId: new ObjectId(req.userId), Status: { $in: statusAtivos } })
            .sort({ Horario: 1 })
            .toArray();
        // A interface espera { success: true, alarmes: [...] }
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error("Erro em /alarmes/ativos:", e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/historico
app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    try {
        // CORREÇÃO: Status de Histórico (string + números)
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];

        const alarmes = await db.collection('alarmes')
            .find({ 
                UserId: new ObjectId(req.userId), 
                Status: { $in: statusDeHistorico } 
            })
            .sort({ Horario: -1 })
            .limit(100)
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error("Erro em /alarmes/historico:", e.message);
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
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/proximos (Usado pelo Serviço de Alarme do Electron)
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
        console.error("Erro em /alarmes/proximos:", e.message);
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Tocar" (disparado pelo main.js)
app.post('/alarmes/tocar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            UserId: new ObjectId(userId)
        });

        if (!alarme) return res.status(404).json({ message: "Alarme não encontrado" });

        // Ao tocar, nós "curamos" o alarme para o novo formato
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
                        Status: "Ativo", // Força o novo status
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
                    $set: { Status: "DisparadoVisto" }, // Força o novo status
                    $unset: {
                        MensagemOriginal: "",
                        HorarioBaseRecorrencia: ""
                    }
                }
            );
        }
        res.json({ success: true, alarmeDisparado: alarme });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Visto" (clicado pelo usuário na notificação)
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
                        Status: "Ativo", // Força o novo status
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
                    $set: { Status: "DisparadoVisto" }, // Força o novo status
                    $unset: {
                        MensagemOriginal: "",
                        HorarioBaseRecorrencia: ""
                    }
                }
            );
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// Rota para "Adiar" (clicado pelo usuário)
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
                Status: "Ativo", // Força o novo status
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
        res.status(500).json({ success: false, message: e.message });
    }
});

// POST /alarmes (Criar)
app.post('/alarmes', autenticarToken, async (req, res) => {
    try {
        const alarme = req.body;
        
        alarme.UserId = new ObjectId(req.userId);
        alarme.Horario = new Date(alarme.Horario);
        alarme.Status = "Ativo"; // Garante o Status novo

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
        alarmeUpdate.Status = "Ativo"; // Garante o Status novo
        
        // Remove campos antigos (se for um alarme adiado sendo salvo)
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
                // Garante que campos de "adiado" sejam limpos ao salvar
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
        res.status(500).json({ success: false, message: e.message });
    }
});

// --- Iniciar Servidor ---
app.listen(port, () => {
    console.log(`API RNLARME rodando na porta ${port}`);
});
