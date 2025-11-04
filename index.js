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
const autenticarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"
    
    if (token == null) return res.sendStatus(401); // Não autorizado

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403); // Token inválido ou expirado
        req.userId = user.userId; // Adiciona o ID do usuário (do payload do token) à requisição
        next();
    });
};

// --- Rotas de Autenticação ---

// Rota de Login
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

        // CORREÇÃO: use 'user.password' (minúsculo)
        const match = await bcrypt.compare(password, user.Password);
        if (match) {
            // Senha correta, gerar token
            const token = jwt.sign(
                { userId: user._id.toString() }, // Salva o ID do usuário no token
                jwtSecret,
                { expiresIn: '30d' } // Token expira em 30 dias
            );
            res.json({ success: true, token: token });
        } else {
            // Senha incorreta
            res.status(401).json({ success: false, message: 'Senha incorreta.' });
        }
    } catch (e) {
        console.error("Erro no /login:", e);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

// (Opcional: Rota para criar usuário, caso precise)
// app.post('/register', async (req, res) => { ... });

// --- Rotas da API de Alarmes ---

// Função Auxiliar de Recorrência (Copiada do seu código original)
function calcularProximaExecucao(baseHorario, tipoRecorrencia, diasSemana = [], diasMes = []) {
    let proximaData = new Date(baseHorario.getTime());
    
    const diasSemanaNum = diasSemana.map(d => parseInt(d)).sort((a, b) => a - b); // [0 (Dom) ... 6 (Sab)]
    const diasMesNum = diasMes.map(d => parseInt(d)).sort((a, b) => a - b); // [1 ... 31]

    const agora = new Date();
    // Garante que o cálculo comece a partir de 'agora' se a base for no passado
    // Isso evita loops infinitos se a base for muito antiga
    if (proximaData <= agora) {
        proximaData = agora;
    }
    
    // Adiciona 1 segundo para garantir que não pegue a data/hora atual exata
    proximaData.setSeconds(proximaData.getSeconds() + 1);

    if (tipoRecorrencia === 'diariamente') {
        proximaData.setDate(proximaData.getDate() + 1);
        
    } else if (tipoRecorrencia === 'semanalmente' && diasSemanaNum.length > 0) {
        const hojeNum = proximaData.getDay(); // Dia da semana atual (0-6)
        
        // Encontra o próximo dia válido nesta semana
        let proximoDiaSemana = diasSemanaNum.find(dia => dia > hojeNum);
        
        if (proximoDiaSemana !== undefined) {
            // Se achou, avança os dias
            proximaData.setDate(proximaData.getDate() + (proximoDiaSemana - hojeNum));
        } else {
            // Se não achou (ex: hoje é sexta, próximo é seg), pega o primeiro da próx. semana
            // Avança para o primeiro dia (ex: segunda, dia 2)
            // (7 - 5) + 2 = 4 dias
            proximaData.setDate(proximaData.getDate() + (7 - hojeNum + diasSemanaNum[0]));
        }

    } else if (tipoRecorrencia === 'mensalmente' && diasMesNum.length > 0) {
        const hojeDia = proximaData.getDate(); // Dia do mês atual (1-31)

        // Encontra o próximo dia válido neste mês
        let proximoDiaMes = diasMesNum.find(dia => dia > hojeDia);
        
        if (proximoDiaMes !== undefined) {
             // Tenta definir para o próximo dia válido neste mês
            let dataTeste = new Date(proximaData.getTime());
            dataTeste.setDate(proximoDiaMes);
            
            // Se o dia (ex: 31) não existir no mês atual (ex: Fev), o JS pula pro próx. mês
            if (dataTeste.getMonth() === proximaData.getMonth()) {
                proximaData.setDate(proximoDiaMes);
            } else {
                // Se pulou o mês (ex: 31 de Fev), pulamos para o próximo mês válido
                // e pegamos o primeiro dia da lista
                proximaData.setMonth(proximaData.getMonth() + 1, diasMesNum[0]);
            }
            
        } else {
            // Não há mais dias válidos este mês, vai pro próximo
            // Pega o primeiro dia válido da lista (ex: dia 5)
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
        const alarmes = await db.collection('alarmes')
            .find({ userId: new ObjectId(req.userId), Status: "Ativo" })
            .sort({ Horario: 1 })
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/historico
app.get('/alarmes/historico', autenticarToken, async (req, res) => {
    try {
        const alarmes = await db.collection('alarmes')
            .find({ userId: new ObjectId(req.userId), Status: "DisparadoVisto" })
            .sort({ Horario: -1 })
            .limit(100)
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// DELETE /alarmes/historico/limpar
app.delete('/alarmes/historico/limpar', autenticarToken, async (req, res) => {
    try {
        await db.collection('alarmes').deleteMany({
            userId: new ObjectId(req.userId),
            Status: "DisparadoVisto"
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// GET /alarmes/proximos (Usado pelo Serviço de Alarme)
app.get('/alarmes/proximos', autenticarToken, async (req, res) => {
    try {
        const agora = new Date();
        const alarmes = await db.collection('alarmes')
            .find({
                userId: new ObjectId(req.userId),
                Status: "Ativo",
                Horario: { $lte: agora } // Pega alarmes com horário vencido
            })
            .toArray();
        res.json({ success: true, alarmes });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// ***************************************************************
// *** ROTAS CORRIGIDAS (BUGS 1 e 1.b) ***
// ***************************************************************

// Rota para "Tocar" (disparado pelo main.js)
app.post('/alarmes/tocar/:id', autenticarToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    try {
        const alarme = await db.collection('alarmes').findOne({
            _id: new ObjectId(id),
            userId: new ObjectId(userId)
        });

        if (!alarme) return res.status(404).json({ message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            
            // CORREÇÃO: Use o 'HorarioBaseRecorrencia' se existir (alarme adiado),
            // senão, use o 'Horario' normal (alarme tocando na hora certa).
            const baseTimeParaCalculo = alarme.HorarioBaseRecorrencia || alarme.Horario;

            const proximaData = calcularProximaExecucao(
                new Date(baseTimeParaCalculo), // <-- USA O HORÁRIO BASE (ex: 8:55)
                alarme.TipoRecorrencia,
                alarme.DiasSemana,
                alarme.DiasMes
            );
            
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) },
                { 
                    $set: { 
                        Horario: proximaData, // Define o próximo horário de disparo (ex: 8:55 de amanhã)
                        Status: "Ativo",
                        Mensagem: alarme.MensagemOriginal || alarme.Mensagem // Restaura a msg original
                    },
                    $unset: {
                        MensagemOriginal: "", // <-- Limpa o campo de "adiado"
                        HorarioBaseRecorrencia: "" // <-- Limpa o campo de "adiado"
                    }
                }
            );
        } else {
            // Alarme não recorrente (também limpa os campos, por segurança)
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) },
                { 
                    $set: { Status: "DisparadoVisto" }, // Marca como "visto"
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
            userId: new ObjectId(userId)
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        if (alarme.IsRecorrente) {
            
            // CORREÇÃO: Lógica IDÊNTICA à rota /tocar
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
                        Horario: proximaData, // Calcula o próximo disparo
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
            // Alarme não recorrente
            await db.collection('alarmes').updateOne(
                { _id: new ObjectId(id) },
                { 
                    $set: { Status: "DisparadoVisto" }, // Apenas marca como visto
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
            userId: new ObjectId(userId)
        });

        if (!alarme) return res.status(404).json({ success: false, message: "Alarme não encontrado" });

        const agora = new Date();
        const novoHorario = new Date(agora.getTime() + parseInt(minutos) * 60000);
        
        // Lógica para salvar os dados originais (se for o primeiro "adiar")
        const msgBase = alarme.MensagemOriginal || alarme.Mensagem;
        
        // CORREÇÃO: Se 'HorarioBaseRecorrencia' NÃO EXISTIR, salve o 'Horario' atual nele.
        // Se já existe, preserve-o (para o caso de múltiplos "adiar").
        const horarioBase = alarme.HorarioBaseRecorrencia || alarme.Horario;

        await db.collection('alarmes').updateOne(
            { _id: new ObjectId(id) },
            { $set: { 
                Horario: novoHorario, // Define o próximo disparo (adiado)
                Status: "Ativo", 
                // IsRecorrente: false,  <--- BUG ORIGINAL (REMOVIDO)
                Mensagem: `(Adiado ${minutos}min) ${msgBase}`, 
                MensagemOriginal: msgBase,
                HorarioBaseRecorrencia: new Date(horarioBase) // <-- SALVA O HORÁRIO ORIGINAL
            }}
        );
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

// ***************************************************************
// *** FIM DAS ROTAS CORRIGIDAS ***
// ***************************************************************


// Rota de Limpeza (Cron Job)
app.get('/tasks/cleanup-old-history', async (req, res) => {
    
    const cronSecret = req.headers['x-cron-secret'];
    if (cronSecret !== process.env.CRON_SECRET) {
        return res.sendStatus(401); // Não autorizado
    }
    
    try {
        const dataLimite = new Date();
        dataLimite.setDate(dataLimite.getDate() - 30);
        
        // CORREÇÃO 3: Remove os números [1, 2, 3] que não são mais usados
        const statusDeHistorico = ["DisparadoVisto"]; 

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
            userId: new ObjectId(req.userId)
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
        
        // Adiciona o ID do usuário e converte o horário
        alarme.userId = new ObjectId(req.userId);
        alarme.Horario = new Date(alarme.Horario);
        
        // Garante o Status
        alarme.Status = "Ativo";

        // Se for recorrente, calcula a primeira data de execução
        if(alarme.IsRecorrente) {
            const agora = new Date();
            // Calcula a próxima data/hora a partir de 'agora'
            // Isso garante que o alarme não seja criado "no passado"
            alarme.Horario = calcularProximaExecucao(
                agora, 
                alarme.TipoRecorrencia, 
                alarme.DiasSemana, 
                alarme.DiasMes
            );
            
            // Define o horário do dia (ex: 8:55)
            const horarioBase = new Date(req.body.Horario); // Pega o horário original (ex: 8:55 de hoje)
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

        // Remove o _id do corpo para evitar erros
        delete alarmeUpdate._id; 
        
        // Converte o horário
        alarmeUpdate.Horario = new Date(alarmeUpdate.Horario);
        // Garante o Status
        alarmeUpdate.Status = "Ativo";
        
        // Se for recorrente, recalcula a próxima data (similar à criação)
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
            { _id: new ObjectId(id), userId: new ObjectId(req.userId) },
            { $set: alarmeUpdate }
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
            userId: new ObjectId(req.userId)
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
