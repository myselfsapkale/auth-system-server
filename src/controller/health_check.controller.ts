import { Request, Response } from 'express';
import { ApiResponse } from '../utils/api_response';
import { async_handler } from '../utils/async_handler';
import logger from '../utils/elk_logger';

const health_check = async_handler(async (req: Request, res: Response) => {
  logger.info(req, 'Health check passed - status: healthy');
  return res.status(200).json(new ApiResponse(200, "OK", "Health check passed!!"))
});

export { health_check };
