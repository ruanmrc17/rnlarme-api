require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb'); 
const express = require('express');
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
    // Reduzindo o spam de log
    // console.log("[LOG Autenticar] Recebendo chamada para:", req.path);
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (token == null) {
        console.error("[LOG Autenticar] ERRO: Token não encontrado.");
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

        req.userId = userIdFromToken.trim(); // req.userId é uma STRING
        // console.log(`[LOG Autenticar] Token OK. UserId (string) definido como: ${req.userId}`);
        
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

// ==================================================================
// Função para calcular a PRÓXIMA data futura.
// (Esta função estava correta na v10)
// ==================================================================
function calcularProximaExecucao(baseHorario, tipoRecorrencia, diasSemana = [], diasMes = []) {
    let proximaData = new Date(); // Começa a calcular a partir de AGORA
    const agora = new Date();
    
    // Pega a HORA e MINUTO desejados do alarme original (ou do input)
    const horarioBase = new Date(baseHorario);
    const hora = horarioBase.getHours();
    const minuto = horarioBase.getMinutes();
    
    // Define a hora/minuto na data de hoje
    proximaData.setHours(hora, minuto, 0, 0);

    // Normalização (caso '0' venha do BD antigo)
    if (tipoRecorrencia === 0) tipoRecorrencia = "Semanal";

    const diasSemanaNum = (diasSemana || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 
    const diasMesNum = (diasMes || []).map(d => parseInt(d)).filter(d => !isNaN(d)).sort((a, b) => a - b); 

    // Loop de segurança: garante que a data calculada esteja no futuro
    // Se proximaData (hoje às 8:30) já passou (ex: agora é 10:00),
    // o loop vai rodar e calcular o *próximo* dia.
    while (proximaData <= agora) {
        let dataBaseLoop = new Date(proximaData.getTime());
        
        if (tipoRecorrencia === 'diariamente') {
            proximaData.setDate(dataBaseLoop.getDate() + 1);
            
        } else if (tipoRecorrencia === 'semanalmente' && diasSemanaNum.length > 0) {
            const hojeNum = dataBaseLoop.getDay();
            let proximoDiaSemana = diasSemanaNum.find(dia => dia > hojeNum); // Procura um dia DEPOIS
            if (proximoDiaSemana !== undefined) {
                // Achou um dia ainda esta semana
                proximaData.setDate(dataBaseLoop.getDate() + (proximoDiaSemana - hojeNum));
            } else {
                // Próxima semana: (7 dias - hoje) + primeiro_dia_valido
                proximaData.setDate(dataBaseLoop.getDate() + (7 - hojeNum + diasSemanaNum[0]));
            }
        } else if (tipoRecorrencia === 'mensalmente' && diasMesNum.length > 0) {
            const hojeDia = dataBaseLoop.getDate();
            let proximoDiaMes = diasMesNum.find(dia => dia > hojeDia); // Procura um dia DEPOIS
            if (proximoDiaMes !== undefined) {
                // Tenta setar no mês atual
                let dataTeste = new Date(dataBaseLoop.getTime());
                dataTeste.setDate(proximoDiaMes);
                
                // Verifica se setar o dia (ex: 31) não pulou o mês
                if (dataTeste.getMonth() === dataBaseLoop.getMonth()) {
                    proximaData.setDate(proximoDiaMes);
                } else {
                    // Pulou (ex: dia 31 em Fev). Vai pro próximo mês
                    proximaData.setMonth(dataBaseLoop.getMonth() + 1, diasMesNum[0]);
                }
            } else {
                // Próximo mês
                proximaData.setMonth(dataBaseLoop.getMonth() + 1, diasMesNum[0]);
            }
        } else {
            // Não recorrente ou dados inválidos (ex: semanal sem dias)
            // Apenas avança 1 dia para sair do loop
            proximaData.setDate(dataBaseLoop.getDate() + 1);
        }
        
        // Re-aplica a hora/minuto na nova data (garante a hora correta)
        proximaData.setHours(hora, minuto, 0, 0);
    }
    
    return proximaData;
}


// Função auxiliar para tentar converter para ObjectId (se falhar, retorna null)
function tryParseObjectId(idString) {
    try {
        if (idString && /^[0-9a-fA-F]{24}$/.test(idString)) {
             return new ObjectId(idString);
        }
    } catch (e) {
        return null;
    }
    return null;
}

// GET /alarmes/ativos
app.get('/alarmes/ativos', autenticarToken, async (req, res) => {
    // console.log(`[LOG /ativos] Tentando carregar. UserId (string) = ${req.userId}`);
    try {
        const statusAtivos = ["Ativo", 0];
        const userIdAsObjectId = tryParseObjectId(req.userId);

        const query = {
            $or: [ { UserId: req.userId }, { UserId: userIdAsObjectId } ],
            Status: { $in: statusAtivos }
        };
        if (!userIdAsObjectId) {
            delete query.$or;
            query.UserId = req.userId;
        }

        const alarmes = await db.collection('alarmes').find(query).sort({ Horario: 1 }).toArray();
        // console.log(`[LOG /ativos] Sucesso. Encontrados ${alarmes.length} alarmes ativos.`);
        res.json({ success: true, alarmes });
    } catch (e) {
        console.error(`[LOG /ativos] ERRO no 'catch' da rota:`, e);
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/historico
app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    // console.log(`[LOG /historico] Tentando carregar. UserId (string) = ${req.userId}`);
    try {
        const statusDeHistorico = ["DisparadoVisto", 1, 2, 3];
        const userIdAsObjectId = tryParseObjectId(req.userId);

        const query = {
            $or: [ { UserId: req.userId }, { UserId: userIdAsObjectId } ],
            Status: { $in: statusDeHistorico }
        };
        if (!userIdAsObjectId) {
            delete query.$or;
            query.UserId = req.userId;
        }

        const alarmes = await db.collection('alarmes').find(query).sort({ Horario: -1 }).limit(100).toArray();
        // console.log(`[LOG /historico] Sucesso. Encontrados ${alarmes.length} itens no histórico.`);
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
        const userIdAsObjectId = tryParseObjectId(req.userId);

        const query = {
            $or: [ { UserId: req.userId }, { UserId: userIdAsObjectId } ],
            Status: { $in: statusDeHistorico }
        };
        if (!userIdAsObjectId) {
            delete query.$or;
            query.UserId = req.userId;
        }
        
        await db.collection('alarmes').deleteMany(query);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// GET /alarmes/proximos
app.get('/alarmes/proximos', autenticarToken, async (req, res) => {
    try {
        const agora = new Date();
        const statusAtivos = ["Ativo", 0];
        const userIdAsObjectId = tryParseObjectId(req.userId);

        const query = {
            $or: [ { UserId: req.userId }, { UserId: userIdAsObjectId } ],
            Status: { $in: statusAtivos },
            Horario: { $lte: agora } 
        };
        if (!userIdAsObjectId) {
            delete query.$or;
            query.UserId = req.userId;
        }

        const alarmes = await db.collection('alarmes').find(query).toArray();
        res.json({ success: true, alarmes });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Rota para "Tocar"
app.post('/alarmes/tocar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params; 
    const userId = req.userId;
    const userIdAsObjectId = tryParseObjectId(userId);

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ]
        });

        if (!alarme) return res.status(404).json({ message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            // =======================================================
            // CORREÇÃO v11.3 - Case Sensitivity
            // =======================================================
            const proximaData = calcularProximaExecucao(
                alarme.HorarioBaseRecorrencia || alarme.Horario, 
                alarme.RecorrenciaTipo, // <-- CORRIGIDO
                alarme.DiasDaSemana,   // <-- CORRIGIDO
                alarme.DiasDoMes       // <-- CORRIGIDO
            );
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) }, 
                { $set: { 
                    Horario: proximaData, Status: "Ativo", 
                    Mensagem: alarme.MensagemOriginal || alarme.Mensagem,
                    UserId: userIdAsObjectId || userId 
                  },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) }, 
                { $set: { 
                    Status: "DisparadoVisto",
                    UserId: userIdAsObjectId || userId
                  }, 
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        }
        res.json({ success: true, alarmeDisparado: alarme });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Rota para "Visto"
app.post('/alarmes/visto/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;
    const userIdAsObjectId = tryParseObjectId(userId);
    
    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ]
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            // =======================================================
            // CORREÇÃO v11.3 - Case Sensitivity
            // =======================================================
            const proximaData = calcularProximaExecucao(
                alarme.HorarioBaseRecorrencia || alarme.Horario, 
                alarme.RecorrenciaTipo, // <-- CORRIGIDO
                alarme.DiasDaSemana,   // <-- CORRIGIDO
                alarme.DiasDoMes       // <-- CORRIGIDO
            );
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) }, 
                { $set: { 
                    Horario: proximaData, Status: "Ativo", 
                    Mensagem: alarme.MensagemOriginal || alarme.Mensagem,
                    UserId: userIdAsObjectId || userId
                  },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        } else {
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) }, 
                { $set: { 
                    Status: "DisparadoVisto",
                    UserId: userIdAsObjectId || userId
                  },
                  $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
            );
        }
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// Rota para "Adiar"
app.post('/alarmes/adiar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;
    const { minutos } = req.body;
    const userIdAsObjectId = tryParseObjectId(userId);

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ]
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        const agora = new Date();
        const novoHorario = new Date(agora.getTime() + parseInt(minutos) * 60000);
        const msgBase = alarme.MensagemOriginal || alarme.Mensagem;
        const horarioBase = alarme.HorarioBaseRecorrencia || alarme.Horario;

        await db.collection('alarmes').updateOne(
            { _id: new ObjectId(id) }, 
            { $set: { 
                Horario: novoHorario, Status: "Ativo", 
                Mensagem: `(Adiado ${minutos}min) ${msgBase}`, 
                MensagemOriginal: msgBase,
                HorarioBaseRecorrencia: new Date(horarioBase),
                UserId: userIdAsObjectId || userId
            }}
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});


// Rota de Limpeza (Cron Job)
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
    const userId = req.userId;
    const userIdAsObjectId = tryParseObjectId(userId);
    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(req.params.id),
            $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ]
        });
        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        res.json({ success: true, alarme });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ==================================================================
// *** CORREÇÃO v11 (BUG: Criação/Edição Recorrente) ***
// Aplicada nas rotas /alarmes (POST) e /alarmes/:id (PUT)
// ==================================================================

// POST /alarmes (Criar)
app.post('/alarmes', autenticarToken, async (req, res) => {
    console.log(`[LOG /alarmes (POST)] Início da rota.`);
    try {
        const alarme = req.body;
        const userIdAsObjectId = tryParseObjectId(req.userId);
        
        console.log("[LOG /alarmes (POST)] Dados recebidos (req.body):");
        console.log(JSON.stringify(alarme, null, 2));

        alarme.UserId = userIdAsObjectId || req.userId; 
        const dataBaseDoInput = new Date(alarme.Horario);
        alarme.Status = "Ativo"; 

        if (alarme.IsRecorrente) {
            console.log("[LOG /alarmes (POST)] 'IsRecorrente' é TRUE. Calculando a primeira ocorrência...");
            // =======================================================
            // CORREÇÃO v11.3 - Case Sensitivity
            // =======================================================
            alarme.Horario = calcularProximaExecucao(
                dataBaseDoInput,
                alarme.RecorrenciaTipo, // <-- CORRIGIDO
                alarme.DiasDaSemana,   // <-- CORRIGIDO
                alarme.DiasDoMes       // <-- CORRIGIDO
            );
            console.log(`[LOG /alarmes (POST)] Nova data calculada: ${alarme.Horario}`);
        } else {
            console.log("[LOG /alarmes (POST)] 'IsRecorrente' é FALSE. Usando data do input.");
            alarme.Horario = dataBaseDoInput;
        }

        const result = await db.collection('alarmes').insertOne(alarme);
        console.log("[LOG /alarmes (POST)] Alarme criado com sucesso.");
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (e) { 
        console.error("[LOG /alarmes (POST)] ERRO no 'catch':", e);
        res.status(500).json({ success: false, message: e.message }); 
    }
});

// ==================================================================
// *** v11.1 DEBUG ***
// Adicionados logs detalhados para investigar o problema do 'Salvar'
// ==================================================================
// PUT /alarmes/:id (Atualizar)
app.put('/alarmes/:id', autenticarToken, async (req, res) => {
    console.log(`[LOG /alarmes (PUT)] Início da rota. ID: ${req.params.id}`);
    try {
        const { id } = req.params; 
        const alarmeUpdate = req.body;
        const userId = req.userId;
        const userIdAsObjectId = tryParseObjectId(userId);

        console.log("[LOG /alarmes (PUT)] Dados recebidos (req.body):");
        console.log(JSON.stringify(alarmeUpdate, null, 2));

        delete alarmeUpdate._id; 
        
        const dataBaseDoInput = new Date(alarmeUpdate.Horario);
        
        alarmeUpdate.Status = "Ativo"; 
        
        alarmeUpdate.UserId = userIdAsObjectId || userId;
        
        delete alarmeUpdate.MensagemOriginal;
        delete alarmeUpdate.HorarioBaseRecorrencia;

        if (alarmeUpdate.IsRecorrente) {
            console.log("[LOG /alarmes (PUT)] 'IsRecorrente' é TRUE. Calculando a primeira ocorrência...");
            
            // =======================================================
            // CORREÇÃO v11.3 - Case Sensitivity
            // =======================================================
            alarmeUpdate.Horario = calcularProximaExecucao(
                dataBaseDoInput,
                alarmeUpdate.RecorrenciaTipo, // <-- CORRIGIDO
                alarmeUpdate.DiasDaSemana,   // <-- CORRIGIDO
                alarmeUpdate.DiasDoMes       // <-- CORRIGIDO
            );
            
            console.log(`[LOG /alarmes (PUT)] Nova data calculada: ${alarmeUpdate.Horario}`);

        } else {
            console.log("[LOG /alarmes (PUT)] 'IsRecorrente' é FALSE. Usando data do input.");
            alarmeUpdate.Horario = dataBaseDoInput;
        }

        const result = await db.collection('alarmes').updateOne(
            { _id: new ObjectId(id), $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ] },
            { $set: alarmeUpdate,
              $unset: { MensagemOriginal: "", HorarioBaseRecorrencia: "" } }
        );
        
        if (result.matchedCount === 0) {
            console.error("[LOG /alarmes (PUT)] ERRO: Alarme não encontrado (matchedCount 0)");
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        
        console.log("[LOG /alarmes (PUT)] Alarme atualizado com sucesso.");
        res.json({ success: true });

    } catch (e) { 
        console.error("[LOG /alarmes (PUT)] ERRO no 'catch':", e);
        res.status(500).json({ success: false, message: e.message }); 
    }
});

// DELETE /alarmes/:id
app.delete('/alarmes/:id', autenticarToken, async (req, res) => {
    try {
        const { id } = req.params; 
        const userId = req.userId;
        const userIdAsObjectId = tryParseObjectId(userId);

        const result = await db.collection('alarmes').deleteOne({
            _id: new ObjectId(id),
            $or: [ { UserId: userId }, { UserId: userIdAsObjectId } ]
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, message: "Alarme não encontrado" });
        }
        res.status(204).send(); 
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- Iniciar Servidor ---
app.listen(port, () => {
    console.log(`API RNLARME rodando na porta ${port}`);
});

